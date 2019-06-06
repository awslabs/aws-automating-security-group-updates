'''
Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0


Automatically update security groups for clusters
Initiated by AutoScaling Lifecycle Hooks and using a DynamoDB
table to sync security groups across regions.
Automatically adds/removes public IPs to security groups in both
regions to enable for secure cross-region communication with publicly
exposed endpoints.
'''
import os
import boto3
import json

def lambda_handler(event, context):
    '''
    Main Lambda Handler
    '''
    print json.dumps(event)
    # Local items
    local_sg = os.environ['local_sg']
    local_region = os.environ['local_region']
    local_table = os.environ['local_table']

    # Remote items
    remote_sg = os.environ['remote_sg']
    remote_region = os.environ['remote_region']
    remote_table = os.environ['remote_table']
    remote_asg = os.environ['remote_asg']

    all_ips = {}
    all_ips['local'] = describe_asg(event)
    print "Retrieved list of public IPs for local ASG"

    # Update our local/remote DynamoDB table for tracking
    all_ips['remote'] = update_dynamo(
        local_table,
        local_region,
        event['detail']['AutoScalingGroupName'],
        remote_table,
        remote_region,
        remote_asg,
        all_ips['local']
    )

    # Updating local region first
    try:
        print "Performing SG updates for local region"
        update_sg(all_ips, local_sg, local_region)
    except Exception as error:
        # if anything goes wrong, catch the exception
        print error
        # signal back the error as we weren't able to update
        # our security group locally
        send_response(event, 'ABANDON')
        return

    # Now update remote region
    try:
        print "Performing SG updates for remote region"
        update_sg(all_ips, remote_sg, remote_region)
    except Exception as error:
        # if anything goes wrong, catch the exception, but
        # continue so remote issues don't affect our ability to
        # launch instances locally
        print error

    # Determining if this was invoked by our Lifecycle Hooks or a trueup
    if "trueup" not in event:
        print "Sending continue back to ASG Lifecycle Hook"
        # only send response back to Lifecycle Hook if this process was triggered
        # by a Lifecycle Hook.  Otherwise it will return an error
        # signal back to autoscaling we're good to go
        send_response(event, 'CONTINUE')

def describe_asg(event):
    '''
    Gets a list of public IPs for all instances in the local ASG
    '''
    # getting list of all instances in ASG
    asg_client = boto3.client('autoscaling')
    describe_asg_response = asg_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[event['detail']['AutoScalingGroupName']],
    )
    instance_ips = []
    ec2_client = boto3.client('ec2')

    # getting the public IPs for all instances in ASG
    for instance in describe_asg_response['AutoScalingGroups'][0]['Instances']:
        # getting details for specific instance
        describe_instance_response = ec2_client.describe_instances(
            InstanceIds=[instance['InstanceId']]
        )
        if not describe_instance_response['Reservations']:
            print "Instance %s doesn't exist" % instance['InstanceId']
            send_response(event, 'ABANDON')
        # omitting instances that are in the terminating state as we need to remove them
        # from the security groups
        if "Terminating" not in instance['LifecycleState']:
            try:
                if 'PublicIpAddress' not in describe_instance_response['Reservations'][0]['Instances'][0]:
                    print "Instance %s doesn't have a public IP address" % instance['InstanceId']
                    continue
                instance_ips.append(describe_instance_response['Reservations'][0]['Instances'][0]['PublicIpAddress']+"/32")
            except Exception as error:
                print error
                # something happened, print error and continue
                continue
    return instance_ips

def update_dynamo(local_table, local_region, local_asg, remote_table, remote_region, remote_asg, local_ips):
    '''
    This method updates the dynamo table for both regions which will serve as the
    source of truth for SG rule comparisons later
    '''
    print "Updating DynamoDB tables"
    # can't update DynamoDB with an empty set so we need to swap this out
    # with a null value if we've removed all instancees
    if not local_ips:
        eav = {"NULL": True}
    else:
        eav = {"SS":local_ips}
    # Updating the local region first
    local_client = boto3.client('dynamodb')
    local_client.update_item(
        TableName=local_table,
        Key={
            'region':{"S":local_region},
            'asg':{"S":local_asg}
        },
        UpdateExpression='SET ips =:ips',
        ExpressionAttributeValues={
            ':ips':eav
        }

    )
    print "Updated local DynamoDB Table"
    # getting the IPs for the remote region from our local DynamoDB table
    remote_ips_response = local_client.get_item(
        TableName=local_table,
        Key={
            'region':{"S":remote_region},
            'asg':{"S":remote_asg}
        }
    )
    # need to do error checking of type returned
    if 'Item' in remote_ips_response and "NULL" not in remote_ips_response['Item']['ips']:
        remote_ips = remote_ips_response['Item']['ips']['SS']
    else:
        remote_ips = []
    print "Retrieved list of remote IPs"
    # Update remote region's DynamoDB table
    try:
        if remote_table != '':
            remote_client = boto3.client('dynamodb', region_name=remote_region)
            remote_client.update_item(
                TableName=remote_table,
                Key={
                    'region':{"S":local_region},
                    'asg':{"S":local_asg}
                },
                UpdateExpression='SET ips =:ips',
                ExpressionAttributeValues={
                    ':ips':eav
                }

            )
            print "Updated remote DynamoDB Table"
        else:
            print "No remote DynamoDB table name, skipping remote update."
    except Exception as error:
        print error
        print "Unable to update remote DynamoDB table.  Continuing to perform local updates to prevent remote issues preventing local operation"

    return remote_ips

def update_sg(all_ips, security_group, region):
    '''
    This function determines what IPs need to be added/removed from the
    passed in security group
    '''
    client = boto3.client('ec2', region_name=region)
    # getting all the rules for the passed in security group
    response = client.describe_security_groups(
        GroupIds=[security_group]
    )

    if not response['SecurityGroups'][0]['IpPermissions']:
        raise Exception("No rules in security group to append new public IP to")
    permissions = response['SecurityGroups'][0]['IpPermissions']

    # creating master list of ips
    combined_ips = all_ips['local']+all_ips['remote']

    # settig our placeholder objects which we'll pass later
    add_permissions = []
    remove_permissions = []

    for permission in permissions:
        # get list of all SG rule IPs
        sg_ips = []
        if permission["IpRanges"]:
            for sg_ip in permission["IpRanges"]:
                sg_ips.append(sg_ip['CidrIp'])

        # blanking out the usergroup pairs so we don't remove the security group
        # rule that's acting as our placeholder
        permission['UserIdGroupPairs'] = []

        # IPs to add to SG
        ips_to_add = list(set(combined_ips).difference(sg_ips))
        if ips_to_add:
            temp_add_permission = permission.copy()
            temp_add_permission["IpRanges"] = [{"CidrIp":s} for s in ips_to_add]
            add_permissions.append(temp_add_permission)

        # IPs to remove from SG
        ips_to_remove = list(set(sg_ips).difference(combined_ips))
        if ips_to_remove:
            temp_remove_permission = permission.copy()
            temp_remove_permission["IpRanges"] = [{"CidrIp":s}  for s in ips_to_remove]
            remove_permissions.append(temp_remove_permission)

    print add_permissions
    if add_permissions:
        print "Adding SG permissions for region %s" % region
        add_sg_permissions(security_group, add_permissions, client)
    else:
        print "No rules to add for region %s" % region
    print remove_permissions
    if remove_permissions:
        print "Removing SG permissions for region %s" % region
        remove_sg_permissions(security_group, remove_permissions, client)
    else:
        print "No rules to remove for region %s" % region

def add_sg_permissions(security_group, permissions, client):
    '''
    Performing the adding of SG rules
    '''
    try:
        client.authorize_security_group_ingress(
            GroupId=security_group,
            IpPermissions=permissions
        )
    except Exception as error:
        print error

def remove_sg_permissions(security_group, permissions, client):
    '''
    Performing the removing of SG rules
    '''
    try:
        client.revoke_security_group_ingress(
            GroupId=security_group,
            IpPermissions=permissions
        )
    except Exception as error:
        print error

def send_response(event, status):
    '''
    Sends the response back to the Lifecycle hooks to CONTINUE or ABANDON
    '''
    client = boto3.client('autoscaling')
    response = client.complete_lifecycle_action(
        LifecycleHookName=event['detail']['LifecycleHookName'],
        AutoScalingGroupName=event['detail']['AutoScalingGroupName'],
        LifecycleActionToken=event['detail']['LifecycleActionToken'],
        LifecycleActionResult=status
    )
    print response

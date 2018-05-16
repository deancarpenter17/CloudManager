# Created by Dean Carpenter

import boto3
import time
from botocore.exceptions import ClientError
from pprint import pprint

from constants import *

class EC2ResourceHandler:

    def __init__(self, region):
        # First, assume the role with the provided credentials
        # TODO: change to dynamically require credentials to be passed in
        self.client = boto3.client('sts')
        try:
            assume_role_response = self.client.assume_role(
                DurationSeconds = SESSION_LENGTH,
                RoleArn = TEST_ROLE_ARN,
                RoleSessionName = TEST_ROLE_SESSION_NAME,
            )
        except ClientError as e:
            print e
            raise e
        # Now use the temporary credentials returned from assume_role to create a boto3 session,
        # which allows us to make AWS API calls
        try:
            self.session = boto3.Session(
                aws_access_key_id = assume_role_response['Credentials']['AccessKeyId'],
                aws_secret_access_key = assume_role_response['Credentials']['SecretAccessKey'],
                aws_session_token = assume_role_response['Credentials']['SessionToken']
            )
        except ClientError as e:
            print e
            raise e

        try:
            self.ec2_client = self.session.client('ec2', region_name=region)
            self.ec2_resource = self.session.resource('ec2', region_name=region)
        except ClientError as e:
            print e
            raise e

    def get_images(self):
        # For now, just return these 5 default images
        # TODO: update to choose any free tier ami
        return FREE_TIER_AMIS
    
    def get_security_groups(self):
        security_groups = []
        
        sec_group_response = self.ec2_client.describe_security_groups(
        	GroupNames=['default']
        	)

        # there always exists at least one default security group per region
        # extract default security group id from the first one in the list
        default_security_group = sec_group_response['SecurityGroups'][0]
        default_security_group_id = default_security_group['GroupId']
        # We also need the VPC ID that this security group is part of
        vpc_id = default_security_group['VpcId']

        try:
            data = self.ec2_client.authorize_security_group_ingress(
                GroupId=default_security_group_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 80,
                     'ToPort': 80,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                # If these permissions already exist for the default sec group, simply ignore the error
                pass

        security_groups.append(default_security_group_id)
        return security_groups

    # build the EC2 Instance
    def create_instance(self, image_name):

        if not image_name:
            print("AMI ID missing..Exiting")
            exit()

        response = self.ec2_client.describe_images(
            Filters=[{
                'Name': 'name',
                'Values': [image_name]}
            ]
        )
        image_id = response['Images'][0]['ImageId']

        security_groups = self.get_security_groups()

        instances = self.ec2_resource.create_instances(
            ImageId=image_id,
            InstanceType=INSTANCE_TYPE,
            MaxCount=1,
            MinCount=1,
            Monitoring={'Enabled': False},
            SecurityGroupIds=security_groups
        )
        # Grab the first instance in the list
        instance = instances[0]

        instance_id = instance.instance_id
        print("Instance ID: " + instance_id)

        print("Starting instance")

        # Public IP/DNS is only available when instance is running
        instance.wait_until_running()

        print("instance is running")

        # Reload the instance attributes so DNS/IP will appear
        instance.load()

        public_dns = instance.public_dns_name
        public_ip = instance.public_ip_address

        print("Public DNS: " + public_dns)
        print("Public IP: " + public_ip)

    def create_key_pair(self):
        pass

def main():
    ec2_handler = EC2ResourceHandler(DEFAULT_REGION)
    images = ec2_handler.get_images()
    image_values = images.values()
    i = 1
    for vals in image_values:
        print(str(i) + ".) " + vals['title'])
        i += 1
    selected_image = raw_input("Please select the image you'd like: ")
    selected_image_name = ""
    if selected_image == '1':
        selected_image_name = image_values[0]['name']
    elif selected_image == '2':
        selected_image_name = image_values[1]['name']
    elif selected_image == '3':
        selected_image_name = image_values[2]['name']
    elif selected_image == '4':
        selected_image_name = image_values[3]['name']
    elif selected_image == '5':
        selected_image_name = image_values[4]['name']

    #print(ec2_handler.get_security_groups())
    ec2_handler.create_instance(image_name=selected_image_name)

if __name__ == '__main__':
    main()

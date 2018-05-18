# Created by Dean Carpenter

import boto3
import time
import random
import string
from botocore.exceptions import ClientError
from pprint import pprint
import os

# Email imports
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

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

        # Initialized in create_instance()
        self.instance = None

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
                     'FromPort': 22,
                     'ToPort': 22,
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

        # create a key-pair so the user can SSH into the instance
        # Public key is saved on AWS, private key is returned here
        key_pair_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))
        private_key = self.create_key_pair(key_pair_name)

        instances = self.ec2_resource.create_instances(
            ImageId=image_id,
            InstanceType=INSTANCE_TYPE,
            KeyName=key_pair_name,
            MaxCount=1,
            MinCount=1,
            Monitoring={'Enabled': False},
            SecurityGroupIds=security_groups
        )
        # Grab the first instance in the list
        self.instance = instances[0]

        instance_id = self.instance.instance_id
        print("Instance ID: " + instance_id)

        print("Starting instance")

        # Public IP/DNS is only available when instance is running
        self.instance.wait_until_running()

        print("instance is running")

        # Reload the instance attributes so DNS/IP will appear
        self.instance.load()

        public_dns = self.instance.public_dns_name
        public_ip = self.instance.public_ip_address

        print("Public DNS: " + public_dns)
        print("Public IP: " + public_ip)

        # Finally, email the user the instance details
        print("Emailing instance details...")
        self.email_instance_details("user@gmail.com", private_key)

    def create_key_pair(self, key_pair_name):
        # TODO: allow the user to choose an existing key-pair or create a new one
        # For now, create a new key-pair every time.
        try:
            key_pair = self.ec2_client.create_key_pair(KeyName=key_pair_name)
        except ClientError as e:
            pass
        else:
            return key_pair

    """
    Once an instance is running, this method emails the instance details to the user, then creates & attaches
    the key_pair.pem file to the email so the user receives these details. It also attaches a custom SSH bash script
    """
    def email_instance_details(self, user_email_address, private_key):
        # instance of MIMEMultipart
        msg = MIMEMultipart()
        msg['From'] = SERVER_EMAIL_ADDRESS
        msg['To'] = user_email_address
        msg['Subject'] = "EC2 Instance Details"

        # Create body of the email
        body = "Attached is the private key and an ssh script for the instance\n\n"
        body += "Instance Details: \n"
        body += "Availability Zone: " + self.instance.placement['AvailabilityZone'] + '\n'
        body += "Instance ID: " + self.instance.instance_id + "\n"
        body += "Instance Type: " + self.instance.instance_type + "\n"
        body += "Public DNS: " + self.instance.public_dns_name + "\n"
        body += "Public IP: " + self.instance.public_ip_address + "\n"
        msg.attach(MIMEText(body, 'plain'))

        key_pair_file_name = private_key['KeyName'] + ".pem"
        k = MIMEBase('application', 'octet-stream')
        s = MIMEBase('application', 'octet-stream')

        # Next, build the .pem file and SSH script to be emailed to the user
        key_pair_pem_file = open(key_pair_file_name, 'a+')
        ssh_script = open('server.sh', 'a+')
        ssh_body = "#!/bin/\n"
        ssh_body += "chmod 400 " + key_pair_file_name + '\n'
        ssh_body += "ssh -i " + key_pair_file_name + " -o ServerAliveInterval=60 " + "ubuntu@" + self.instance.public_dns_name
        try:
            key_pair_pem_file.write(private_key['KeyMaterial'])
            ssh_script.write(ssh_body)
            # To change the payload into encoded form
            key_pair_pem_file.seek(0)
            ssh_script.seek(0)
            k.set_payload(key_pair_pem_file.read())
            s.set_payload(ssh_script.read())
            # clean up the server's directory
            os.remove(key_pair_file_name)
            os.remove("server.sh")
        except IOError as e:
            print("Error creating .pem file")
            raise e
        finally:
            key_pair_pem_file.close()

        # encode into base64
        encoders.encode_base64(k)
        encoders.encode_base64(s)
        k.add_header('Content-Disposition', "attachment; filename= %s" % key_pair_file_name)
        s.add_header('Content-Disposition', "attachment; filename= %s" % "server.sh")
        # attach the instance 'p' to instance 'msg'
        msg.attach(k)
        msg.attach(s)

        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.ehlo()
            server.login(SERVER_EMAIL_ADDRESS, SERVER_EMAIL_PASSWORD)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.close()
        except Exception as e:
            print e
            raise e

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

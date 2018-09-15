Python program that automatically creates an Amazon EC2 VM. Once a VM is created, it emails the user the public IP/DNS and other instance details, along with an SSH script and the .pem key-file. This allows the user to quickly SSH into the server and removes a lot of the steps involved when creating a VM. 

# NOTE:
This python program is missing a "constants.py" file that includes sensitive information needed about your AWS account. This was not included for obvious reasons.

This project is still in the works, I'm currently creating an iOS frontend so you can manage your VM's from your phone. I'm also making the code more generic to allow for more options when creating VMs. 

	1.	ConnectivityChecker class:
	•	Initializes Boto3 clients (EC2, STS) to retrieve details about the target instance.
	•	Gathers relevant networking data (public IP, security groups, inbound/outbound rules).
	•	Performs optional checks of port availability via TCP connect.
	•	(Optionally) can attempt SSH connectivity via Paramiko.
	2.	ConnectivityReport data:
	•	Returns or prints a comprehensive status describing which ports are open to the world, whether SSH is allowed, and whether an SSH attempt actually succeeded.
	3.	Usage:
	•	Requires AWS credentials to be configured.
	•	If you want to actually attempt SSH, install Paramiko (pip install paramiko) and provide your .pem path.
	•	For a quick usage from command line, you might do:

    ```python connectivity_checker.py --instance-id i-1234567890abcdef --region us-west-2 \
   --ssh-key-path ~/.ssh/MyKeyPair.pem \
   --ssh-username ec2-user```
   (This example expects that your AWS creds and config are set up via environment or ~/.aws/credentials.)

Key Points & Extensions
	1.	Security Group Inspection
	•	We parse inbound rules to see what’s allowed from 0.0.0.0/0—that indicates publicly open.
	•	Port ranges (FromPort/ToPort) are handled; if -1, it often indicates “all ports”.
	2.	TCP Port Check (check_port_open)
	•	Uses a Python socket to attempt a handshake. If it succeeds, the port is “open”. This test only works if the instance has a reachable public IP (and your local environment can route to it).
	3.	SSH Connectivity
	•	Relies on Paramiko for an actual SSH attempt.
	•	Provide the .pem path and the username (commonly ec2-user or ubuntu, etc. depending on AMI).
	4.	Usability
	•	The code can be expanded easily for checks on custom ports or service-level validations (e.g., verifying HTTP responses on port 80).
	•	You can incorporate logging or a more robust output structure (e.g. JSON) if you need to parse the results.
	5.	Future Enhancements
	•	Query route tables or NAT gateways to confirm that the instance truly has internet access for outbound requests.
	•	Add compliance checks (e.g., ensure no wide-open port ranges in production).
	•	Integrate better error handling or a dedicated logging framework.
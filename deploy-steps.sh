./build-s3-dist.sh -b 5pillars-playbooks -v 1.4.2.1
./upload_s3_dist.sh ap-southeast-2
aws s3 sync ./global-s3-assets s3://5pillars-playbooks-reference/aws-security-hub-automated-response-and-remediation/latest/
aws s3 sync ./global-s3-assets s3://5pillars-playbooks-reference/aws-security-hub-automated-response-and-remediation/v1.4.2.1/
cd deployment
chmod +x ./build-s3-dist.sh
./build-s3-dist.sh -b 5pillars-uat-playbooks -c v2.1.3.7
./build-s3-dist.sh -b 5pillars-uat-playbooks -v v2.1.3.7
chmod +x ./upload-s3-dist.sh
./upload-s3-dist.sh ap-southeast-1
./upload-s3-dist.sh ap-southeast-2
./upload-s3-dist.sh ap-southeast-4
./upload-s3-dist.sh ap-northeast-1
./upload-s3-dist.sh ap-south-1
./upload-s3-dist.sh us-east-1
./upload-s3-dist.sh us-east-2
./upload-s3-dist.sh us-west-1
./upload-s3-dist.sh us-west-2
./upload-s3-dist.sh eu-west-1
./upload-s3-dist.sh eu-west-2
./upload-s3-dist.sh eu-central-1
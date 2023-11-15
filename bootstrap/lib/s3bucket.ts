import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';

export interface S3BucketProps {
    bucketName: string;
    allowedAccounts: string[];
}
  
export class S3Bucket extends Construct {

    bucket: s3.Bucket
    principals: iam.AccountPrincipal[] = [];

    constructor(scope: Construct, id: string, props: S3BucketProps) {
      super(scope, id);

      props.allowedAccounts.forEach((account) => {
        this.principals.push(new iam.AccountPrincipal(account))
      });
  
  
      this.bucket = new s3.Bucket(this, `SECOPS-ASR-S3Bucket-${props.bucketName}`, {
        removalPolicy: cdk.RemovalPolicy.DESTROY, 
        bucketName: props.bucketName,
        versioned: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      });
  
      const s3Policy = new iam.PolicyStatement({
        actions: ['s3:GetObject'],
        resources: [`arn:aws:s3:::${props.bucketName}/*`],
        principals: this.principals, 
      });
  
      this.bucket.addToResourcePolicy(s3Policy);
  
      // It prints the Bucket URL per region.
      new cdk.CfnOutput(this, `S3BucketURL-${props.bucketName}`, {
        value: this.bucket.bucketDomainName,
        description: `BucketBane ${props.bucketName}`,
      });

    }
}

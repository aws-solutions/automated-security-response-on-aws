import * as cdk from 'aws-cdk-lib';
import { S3Bucket } from './s3bucket';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';

export interface S3BucketStackProps extends cdk.StackProps {
  bucketName: string
  allowedAccounts: string[]
}

export class S3BucketStack extends cdk.Stack{

  bucket: s3.Bucket
  
  constructor(scope: Construct, id: string, props: S3BucketStackProps) {
    super(scope, id, props);
    
    this.bucket = new S3Bucket(this, `S3Bucket-${props.bucketName}`, {
      allowedAccounts: props.allowedAccounts,
      bucketName: props.bucketName
    }).bucket;

  }
}

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';

/*
  Bootstrap properties
*/
interface BootstrapWithPolicyProps extends cdk.StackProps{
  bucketName: string;
  organizationId: string;
}

export class BootstrapStack extends cdk.Stack {

  organizationId: string

  constructor(scope: Construct, id: string, props: BootstrapWithPolicyProps) {
    super(scope, id, props);
    this.organizationId = props.organizationId;

    const s3Bucket = new s3.Bucket(this, `SECOPS-ASR-S3Bucket-${this.region}`, {
      removalPolicy: cdk.RemovalPolicy.DESTROY, 
      bucketName: props.bucketName,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });

    s3Bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ['s3:*'],
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        resources: [
          s3Bucket.bucketArn,
          s3Bucket.bucketArn + '/*'
        ],
        conditions: {
          StringEquals: {
            'aws:PrincipalOrgID': this.organizationId,
            },
        },
      })
    );

    // It prints the Bucket URL per region.
    new cdk.CfnOutput(this, `S3BucketURL-${this.region}`, {
      value: s3Bucket.bucketDomainName,
      description: `Bucket URL in ${this.region}`,
    });
  }
}

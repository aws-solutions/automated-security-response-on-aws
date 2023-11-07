#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { BootstrapStack } from '../lib/bootstrap-stack';

const bucketId = process.env.BUCKET_ID as string
const orgId = process.env.ORG_ID as string
// TODO: It is missing to parametrize the list of the allowed regions.
const allowedRegions = ["us-west-2", "us-west-1", "us-east-2", "us-east-1", "eu-west-2", "eu-north-1", "eu-central-1", "ap-southeast-2", "ap-southeast-1", "ap-south-1"]
const app = new cdk.App();

// Regional bootstrap stacks
allowedRegions.forEach((region, index) => {
  new BootstrapStack(app, `SECOPS-ASR-BootstrapStack-${region}`, {
    env: {
      region: region
    },
    bucketName: `cf-templates-asr-${bucketId}-${region.toLowerCase()}`,
    organizationId: orgId
  });
});

// Global bootstrap stack
new BootstrapStack(app, "SECOPS-ASR-BootstrapStack-Global", {
  env: {
    region: process.env.CDK_DEFAULT_REGION
  },
  bucketName: `cf-templates-asr-${bucketId}-reference`,
  organizationId: orgId
});
#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { S3BucketStack } from '../lib/stack-bucket';
import { StackSetAutomation } from '../lib/stackset-automation';
import { StackSetAutomationConfig } from '../lib/stackset-interface';

const app = new cdk.App();

const regions: string[] = app.node.getContext("regions").split(",");
const bucketIdName = app.node.getContext("bucketid");
const allowedAccounts = app.node.getContext("accounts").split(",");
const payerId = app.node.getContext("payerid");
const bucketKey = "aws-security-hub-automated-response-and-remediation/v2.0.2";


// S3Buckets needed for the ASR solution
regions.forEach((region) => {
  new S3BucketStack(app, `SECOPS-BootstrapASRStack-${region}`, {
    env: { 
      account: process.env.CDK_DEFAULT_ACCOUNT, 
      region: region
    },
    bucketName: `cf-templates-asr-${bucketIdName}-${region}`,
    allowedAccounts: allowedAccounts
  });
});

// S3Bucket deployment for the administrator ASR solution
const adminBucket = new S3BucketStack(app, `SECOPS-BootstrapASRStack-reference`, {
    env: { 
      account: process.env.CDK_DEFAULT_ACCOUNT, 
      region: process.env.CDK_DEFAULT_REGION
    },
    bucketName: `cf-templates-asr-${bucketIdName}-reference`,
    allowedAccounts: allowedAccounts
});

 // Automation StackSet configuration
 const administratorParams = [
     'ParameterKey=LoadAFSBPAdminStack,ParameterValue=yes',
     'ParameterKey=LoadCIS120AdminStack,ParameterValue=yes',
     'ParameterKey=LoadCIS140AdminStack,ParameterValue=no',
     'ParameterKey=LoadPCI321AdminStack,ParameterValue=yes',
     'ParameterKey=LoadSCAdminStack,ParameterValue=yes',
     'ParameterKey=ReuseOrchestratorLogGroup,ParameterValue=yes',
 ];
 const adminTemplateName = "aws-sharr-deploy";
const adminStackSetConfig = getStackSetConfig(
  adminTemplateName, 
  administratorParams, 
  "Administrator", 
  "(SO0111R) AWS Security Hub Automated Response & Remediation Administrator, v2.0.2 customized by Lytx",
  false,
  bucketKey
);
if(adminStackSetConfig){
  new StackSetAutomation(app, "SECOPS-ASR-StackSetAutomation-Administrator",{
    env: { 
      account: process.env.CDK_DEFAULT_ACCOUNT, 
      region: process.env.CDK_DEFAULT_REGION 
    },
    stackSetConfig: adminStackSetConfig,
    Bucket: adminBucket.bucket,
    BucketIdName: bucketIdName
  });
}

const memberRolesParams = [
  `ParameterKey=SecHubAdminAccount,ParameterValue=${process.env.CDK_DEFAULT_ACCOUNT}`
];
const memberRolesTemplateName = "aws-sharr-member-roles";
const remediationRoleStackSetConfig = getStackSetConfig(
  memberRolesTemplateName, 
  memberRolesParams, 
  "RemediationRole", 
  "(SO0111M) AWS Security Hub Automated Response & Remediation Member Roles Stack, v2.0.2 customized by Lytx",
  true,
  bucketKey,
  "Payer",
  payerId
);
if(remediationRoleStackSetConfig){
  new StackSetAutomation(app, "SECOPS-ASR-StackSetAutomation-RemediationRole",{
    env: { 
      account: process.env.CDK_DEFAULT_ACCOUNT, 
      region: process.env.CDK_DEFAULT_REGION 
    },
    stackSetConfig: remediationRoleStackSetConfig,
    Bucket: adminBucket.bucket,
    BucketIdName: bucketIdName
  });
}


const memberParams = [
  `ParameterKey=SecHubAdminAccount,ParameterValue=${process.env.CDK_DEFAULT_ACCOUNT}`,
  'ParameterKey=LogGroupName,ParameterValue=/aws/securityhub/',
  'ParameterKey=LoadSCMemberStack,ParameterValue=yes',
  'ParameterKey=LoadPCI321MemberStack,ParameterValue=yes',
  'ParameterKey=LoadCIS140MemberStack,ParameterValue=yes',
  'ParameterKey=LoadCIS120MemberStack,ParameterValue=yes',
  'ParameterKey=LoadAFSBPMemberStack,ParameterValue=yes',
  'ParameterKey=CreateS3BucketForRedshiftAuditLogging,ParameterValue=no',
];
const memberTemplateName = "aws-sharr-member";
const memberAccountsStackSetConfig = getStackSetConfig(
  memberTemplateName, 
  memberParams, 
  "Runbook-MemberAccounts", 
  "(SO0111M) AWS Security Hub Automated Response & Remediation Member Account Stack, v2.0.2 customized by Lytx",
  false,
  bucketKey
);
if(memberAccountsStackSetConfig){
  new StackSetAutomation(app, "SECOPS-ASR-StackSetAutomation-Runbook-MemberAccounts",{
    env: { 
      account: process.env.CDK_DEFAULT_ACCOUNT, 
      region: process.env.CDK_DEFAULT_REGION 
    },
    stackSetConfig: memberAccountsStackSetConfig,
    Bucket: adminBucket.bucket,
    BucketIdName: bucketIdName
  });
}

function getStackSetConfig(
  templateName: string, 
  paramsStack: string[], 
  stackSetId: string, 
  stackSetDesc: string, 
  templateFromS3: boolean,
  bucketKey: string,
  targetAccountName?: string, 
  targetAccountId?: string) :StackSetAutomationConfig {
  
  const targetAccounts = new Map<string, string>();
  if(targetAccountName && targetAccountId) {
      targetAccounts.set(targetAccountName, targetAccountId);
  }
  // Configuration for the administrator StackSet 
  const stackSetConfig: StackSetAutomationConfig = {
      BucketKey: bucketKey, // default value
      StackSetId: stackSetId,
      StackSetParameters: paramsStack,
      StackSetName: `SECOPS-AWS-SecurityHub-AutomatedResponseAndRemediation-${stackSetId}-StackSet`,
      TemplateName: templateName ,
      TemplateDescription: stackSetDesc,
      TemplateFromS3: templateFromS3,
      TargetAccounts: targetAccounts,
  };
  return stackSetConfig;
}
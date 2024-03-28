// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CfnCondition, CfnParameter, Fn } from 'aws-cdk-lib';

import * as autoscaling_1 from '../ssmdocs/NIST80053_AutoScaling.1';
import * as cloudformation_1 from '../ssmdocs/NIST80053_CloudFormation.1';
import * as cloudfront_1 from '../ssmdocs/NIST80053_CloudFront.1';
import * as cloudfront_12 from '../ssmdocs/NIST80053_CloudFront.12';
import * as cloudtrail_1 from '../ssmdocs/NIST80053_CloudTrail.1';
import * as cloudtrail_2 from '../ssmdocs/NIST80053_CloudTrail.2';
import * as cloudtrail_4 from '../ssmdocs/NIST80053_CloudTrail.4';
import * as cloudtrail_5 from '../ssmdocs/NIST80053_CloudTrail.5';
import * as codebuild_2 from '../ssmdocs/NIST80053_CodeBuild.2';
import * as codebuild_5 from '../ssmdocs/NIST80053_CodeBuild.5';
import * as config_1 from '../ssmdocs/NIST80053_Config.1';
import * as ec2_1 from '../ssmdocs/NIST80053_EC2.1';
import * as ec2_2 from '../ssmdocs/NIST80053_EC2.2';
import * as ec2_4 from '../ssmdocs/NIST80053_EC2.4';
import * as ec2_6 from '../ssmdocs/NIST80053_EC2.6';
import * as ec2_7 from '../ssmdocs/NIST80053_EC2.7';
import * as ec2_8 from '../ssmdocs/NIST80053_EC2.8';
import * as ec2_13 from '../ssmdocs/NIST80053_EC2.13';
import * as ec2_15 from '../ssmdocs/NIST80053_EC2.15';
import * as ec2_18 from '../ssmdocs/NIST80053_EC2.18';
import * as ec2_19 from '../ssmdocs/NIST80053_EC2.19';
import * as ec2_23 from '../ssmdocs/NIST80053_EC2.23';
import * as ecr_1 from '../ssmdocs/NIST80053_ECR.1';
import * as guardduty_1 from '../ssmdocs/NIST80053_GuardDuty.1';
import * as iam_3 from '../ssmdocs/NIST80053_IAM.3';
import * as iam_7 from '../ssmdocs/NIST80053_IAM.7';
import * as iam_8 from '../ssmdocs/NIST80053_IAM.8';
import * as kms_4 from '../ssmdocs/NIST80053_KMS.4';
import * as lambda_1 from '../ssmdocs/NIST80053_Lambda.1';
import * as rds_1 from '../ssmdocs/NIST80053_RDS.1';
import * as rds_2 from '../ssmdocs/NIST80053_RDS.2';
import * as rds_4 from '../ssmdocs/NIST80053_RDS.4';
import * as rds_5 from '../ssmdocs/NIST80053_RDS.5';
import * as rds_6 from '../ssmdocs/NIST80053_RDS.6';
import * as rds_7 from '../ssmdocs/NIST80053_RDS.7';
import * as rds_8 from '../ssmdocs/NIST80053_RDS.8';
import * as rds_13 from '../ssmdocs/NIST80053_RDS.13';
import * as rds_16 from '../ssmdocs/NIST80053_RDS.16';
import * as redshift_1 from '../ssmdocs/NIST80053_Redshift.1';
import * as redshift_3 from '../ssmdocs/NIST80053_Redshift.3';
import * as redshift_4 from '../ssmdocs/NIST80053_Redshift.4';
import * as redshift_6 from '../ssmdocs/NIST80053_Redshift.6';
import * as s3_1 from '../ssmdocs/NIST80053_S3.1';
import * as s3_2 from '../ssmdocs/NIST80053_S3.2';
import * as s3_4 from '../ssmdocs/NIST80053_S3.4';
import * as s3_5 from '../ssmdocs/NIST80053_S3.5';
import * as s3_6 from '../ssmdocs/NIST80053_S3.6';
import * as s3_9 from '../ssmdocs/NIST80053_S3.9';
import * as s3_11 from '../ssmdocs/NIST80053_S3.11';
import * as s3_13 from '../ssmdocs/NIST80053_S3.13';
import * as secretsmanager_1 from '../ssmdocs/NIST80053_SecretsManager.1';
import * as secretsmanager_3 from '../ssmdocs/NIST80053_SecretsManager.3';
import * as secretsmanager_4 from '../ssmdocs/NIST80053_SecretsManager.4';
import * as sqs_1 from '../ssmdocs/NIST80053_SQS.1';
import * as sns_1 from '../ssmdocs/NIST80053_SNS.1';
import * as sns_2 from '../ssmdocs/NIST80053_SNS.2';
import * as ssm_4 from '../ssmdocs/NIST80053_SSM.4';

export interface PlaybookProps {
  standardShortName: string;
  standardLongName: string;
  standardVersion: string;
  runtimePython: Runtime;
  solutionId: string;
  solutionAcronym: string;
  solutionVersion: string;
}

export class ControlRunbooks extends Construct {
  protected readonly standardLongName: string;
  protected readonly standardVersion: string;
  protected controls: Set<string> = new Set<string>();

  constructor(scope: Construct, id: string, props: PlaybookProps) {
    super(scope, id);

    this.standardLongName = props.standardLongName;
    this.standardVersion = props.standardVersion;

    this.add(autoscaling_1.createControlRunbook(this, 'AutoScaling.1', props));
    this.add(cloudformation_1.createControlRunbook(this, 'CloudFormation.1', props));
    this.add(cloudfront_1.createControlRunbook(this, 'CloudFront.1', props));
    this.add(cloudfront_12.createControlRunbook(this, 'CloudFront.12', props));
    this.add(cloudtrail_1.createControlRunbook(this, 'CloudTrail.1', props));
    this.add(cloudtrail_2.createControlRunbook(this, 'CloudTrail.2', props));
    this.add(cloudtrail_4.createControlRunbook(this, 'CloudTrail.4', props));
    this.add(cloudtrail_5.createControlRunbook(this, 'CloudTrail.5', props));
    this.add(codebuild_2.createControlRunbook(this, 'CodeBuild.2', props));
    this.add(codebuild_5.createControlRunbook(this, 'CodeBuild.5', props));
    this.add(config_1.createControlRunbook(this, 'Config.1', props));
    this.add(ec2_1.createControlRunbook(this, 'EC2.1', props));
    this.add(ec2_2.createControlRunbook(this, 'EC2.2', props));
    this.add(ec2_4.createControlRunbook(this, 'EC2.4', props));
    this.add(ec2_6.createControlRunbook(this, 'EC2.6', props));
    this.add(ec2_7.createControlRunbook(this, 'EC2.7', props));
    this.add(ec2_8.createControlRunbook(this, 'EC2.8', props));
    this.add(ec2_13.createControlRunbook(this, 'EC2.13', props));
    this.add(ec2_15.createControlRunbook(this, 'EC2.15', props));
    this.add(ec2_18.createControlRunbook(this, 'EC2.18', props));
    this.add(ec2_19.createControlRunbook(this, 'EC2.19', props));
    this.add(ec2_23.createControlRunbook(this, 'EC2.23', props));
    this.add(ecr_1.createControlRunbook(this, 'ECR.1', props));
    this.add(guardduty_1.createControlRunbook(this, 'GuardDuty.1', props));
    this.add(iam_3.createControlRunbook(this, 'IAM.3', props));
    this.add(iam_7.createControlRunbook(this, 'IAM.7', props));
    this.add(iam_8.createControlRunbook(this, 'IAM.8', props));
    this.add(kms_4.createControlRunbook(this, 'KMS.4', props));
    this.add(lambda_1.createControlRunbook(this, 'Lambda.1', props));
    this.add(rds_1.createControlRunbook(this, 'RDS.1', props));
    this.add(rds_2.createControlRunbook(this, 'RDS.2', props));
    this.add(rds_4.createControlRunbook(this, 'RDS.4', props));
    this.add(rds_5.createControlRunbook(this, 'RDS.5', props));
    this.add(rds_6.createControlRunbook(this, 'RDS.6', props));
    this.add(rds_7.createControlRunbook(this, 'RDS.7', props));
    this.add(rds_8.createControlRunbook(this, 'RDS.8', props));
    this.add(rds_13.createControlRunbook(this, 'RDS.13', props));
    this.add(rds_16.createControlRunbook(this, 'RDS.16', props));
    this.add(redshift_1.createControlRunbook(this, 'Redshift.1', props));
    this.add(redshift_3.createControlRunbook(this, 'Redshift.3', props));
    this.add(redshift_4.createControlRunbook(this, 'Redshift.4', props));
    this.add(redshift_6.createControlRunbook(this, 'Redshift.6', props));
    this.add(s3_1.createControlRunbook(this, 'S3.1', props));
    this.add(s3_2.createControlRunbook(this, 'S3.2', props));
    this.add(s3_4.createControlRunbook(this, 'S3.4', props));
    this.add(s3_5.createControlRunbook(this, 'S3.5', props));
    this.add(s3_6.createControlRunbook(this, 'S3.6', props));
    this.add(s3_9.createControlRunbook(this, 'S3.9', props));
    this.add(s3_11.createControlRunbook(this, 'S3.11', props));
    this.add(s3_13.createControlRunbook(this, 'S3.13', props));
    this.add(secretsmanager_1.createControlRunbook(this, 'SecretsManager.1', props));
    this.add(secretsmanager_3.createControlRunbook(this, 'SecretsManager.3', props));
    this.add(secretsmanager_4.createControlRunbook(this, 'SecretsManager.4', props));
    this.add(sns_1.createControlRunbook(this, 'SNS.1', props));
    this.add(sns_2.createControlRunbook(this, 'SNS.2', props));
    this.add(sqs_1.createControlRunbook(this, 'SQS.1', props));
    this.add(ssm_4.createControlRunbook(this, 'SSM.4', props));
  }

  protected add(document: ControlRunbookDocument) {
    const controlId = document.getControlId();
    const enableParamDescription = this.getEnableParamDescription(controlId);
    const enableParamValueAvailable = 'Available';
    const enableParam = new CfnParameter(this, `Enable ${controlId}`, {
      type: 'String',
      description: enableParamDescription,
      default: enableParamValueAvailable,
      allowedValues: [enableParamValueAvailable, 'NOT Available'],
    });

    const installSsmDoc = new CfnCondition(this, `Enable ${controlId} Condition`, {
      expression: Fn.conditionEquals(enableParam, enableParamValueAvailable),
    });

    document.cfnDocument.cfnOptions.condition = installSsmDoc;

    this.controls.add(document.getControlId());
  }

  protected getEnableParamDescription(controlId: string) {
    // eslint-disable-next-line prettier/prettier
    return (
      `Enable/disable availability of remediation for ${this.standardLongName} version ` +
      `${this.standardVersion} Control ${controlId} in Security Hub Console Custom Actions. If ` +
      'NOT Available the remediation cannot be triggered from the Security Hub console in the ' +
      'Security Hub Admin account.'
    );
  }

  public has(controlId: string): boolean {
    return this.controls.has(controlId);
  }
}

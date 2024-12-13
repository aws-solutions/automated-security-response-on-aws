// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CfnCondition, CfnParameter, Fn } from 'aws-cdk-lib';

import * as apigateway_5 from '../ssmdocs/NIST80053_APIGateway.5';
import * as autoscaling_1 from '../ssmdocs/NIST80053_AutoScaling.1';
import * as autoscaling_3 from '../ssmdocs/NIST80053_AutoScaling.3';
import * as autoscaling_5 from '../ssmdocs/NIST80053_Autoscaling.5'; // intentionally different casing to match SecurityHub generator id
import * as cloudformation_1 from '../ssmdocs/NIST80053_CloudFormation.1';
import * as cloudfront_1 from '../ssmdocs/NIST80053_CloudFront.1';
import * as cloudfront_12 from '../ssmdocs/NIST80053_CloudFront.12';
import * as cloudtrail_1 from '../ssmdocs/NIST80053_CloudTrail.1';
import * as cloudtrail_2 from '../ssmdocs/NIST80053_CloudTrail.2';
import * as cloudtrail_4 from '../ssmdocs/NIST80053_CloudTrail.4';
import * as cloudtrail_5 from '../ssmdocs/NIST80053_CloudTrail.5';
import * as cloudwatch_16 from '../ssmdocs/NIST80053_CloudWatch.16';
import * as codebuild_2 from '../ssmdocs/NIST80053_CodeBuild.2';
import * as codebuild_5 from '../ssmdocs/NIST80053_CodeBuild.5';
import * as config_1 from '../ssmdocs/NIST80053_Config.1';
import * as ec2_1 from '../ssmdocs/NIST80053_EC2.1';
import * as ec2_2 from '../ssmdocs/NIST80053_EC2.2';
import * as ec2_4 from '../ssmdocs/NIST80053_EC2.4';
import * as ec2_6 from '../ssmdocs/NIST80053_EC2.6';
import * as ec2_7 from '../ssmdocs/NIST80053_EC2.7';
import * as ec2_8 from '../ssmdocs/NIST80053_EC2.8';
import * as ec2_10 from '../ssmdocs/NIST80053_EC2.10';
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
import * as macie_1 from '../ssmdocs/NIST80053_Macie.1';
import { IControl } from '../../../lib/sharrplaybook-construct';

export interface PlaybookProps {
  standardShortName: string;
  standardLongName: string;
  standardVersion: string;
  runtimePython: Runtime;
  solutionId: string;
  solutionAcronym: string;
  solutionVersion: string;
  remediations: IControl[];
  namespace: string;
}

const controlRunbooksRecord: Record<string, any> = {
  'APIGateway.5': apigateway_5.createControlRunbook,
  'AutoScaling.1': autoscaling_1.createControlRunbook,
  'AutoScaling.3': autoscaling_3.createControlRunbook,
  'Autoscaling.5': autoscaling_5.createControlRunbook,
  'CloudFormation.1': cloudformation_1.createControlRunbook,
  'CloudFront.1': cloudfront_1.createControlRunbook,
  'CloudFront.12': cloudfront_12.createControlRunbook,
  'CloudTrail.1': cloudtrail_1.createControlRunbook,
  'CloudTrail.2': cloudtrail_2.createControlRunbook,
  'CloudTrail.4': cloudtrail_4.createControlRunbook,
  'CloudTrail.5': cloudtrail_5.createControlRunbook,
  'CloudWatch.16': cloudwatch_16.createControlRunbook,
  'CodeBuild.2': codebuild_2.createControlRunbook,
  'CodeBuild.5': codebuild_5.createControlRunbook,
  'Config.1': config_1.createControlRunbook,
  'EC2.1': ec2_1.createControlRunbook,
  'EC2.2': ec2_2.createControlRunbook,
  'EC2.4': ec2_4.createControlRunbook,
  'EC2.6': ec2_6.createControlRunbook,
  'EC2.7': ec2_7.createControlRunbook,
  'EC2.8': ec2_8.createControlRunbook,
  'EC2.10': ec2_10.createControlRunbook,
  'EC2.13': ec2_13.createControlRunbook,
  'EC2.15': ec2_15.createControlRunbook,
  'EC2.18': ec2_18.createControlRunbook,
  'EC2.19': ec2_19.createControlRunbook,
  'EC2.23': ec2_23.createControlRunbook,
  'ECR.1': ecr_1.createControlRunbook,
  'GuardDuty.1': guardduty_1.createControlRunbook,
  'IAM.3': iam_3.createControlRunbook,
  'IAM.7': iam_7.createControlRunbook,
  'IAM.8': iam_8.createControlRunbook,
  'KMS.4': kms_4.createControlRunbook,
  'Lambda.1': lambda_1.createControlRunbook,
  'RDS.1': rds_1.createControlRunbook,
  'RDS.2': rds_2.createControlRunbook,
  'RDS.4': rds_4.createControlRunbook,
  'RDS.5': rds_5.createControlRunbook,
  'RDS.6': rds_6.createControlRunbook,
  'RDS.7': rds_7.createControlRunbook,
  'RDS.8': rds_8.createControlRunbook,
  'RDS.13': rds_13.createControlRunbook,
  'RDS.16': rds_16.createControlRunbook,
  'Redshift.1': redshift_1.createControlRunbook,
  'Redshift.3': redshift_3.createControlRunbook,
  'Redshift.4': redshift_4.createControlRunbook,
  'Redshift.6': redshift_6.createControlRunbook,
  'S3.1': s3_1.createControlRunbook,
  'S3.2': s3_2.createControlRunbook,
  'S3.4': s3_4.createControlRunbook,
  'S3.5': s3_5.createControlRunbook,
  'S3.6': s3_6.createControlRunbook,
  'S3.9': s3_9.createControlRunbook,
  'S3.11': s3_11.createControlRunbook,
  'S3.13': s3_13.createControlRunbook,
  'SecretsManager.1': secretsmanager_1.createControlRunbook,
  'SecretsManager.3': secretsmanager_3.createControlRunbook,
  'SecretsManager.4': secretsmanager_4.createControlRunbook,
  'SQS.1': sqs_1.createControlRunbook,
  'SNS.1': sns_1.createControlRunbook,
  'SNS.2': sns_2.createControlRunbook,
  'SSM.4': ssm_4.createControlRunbook,
  'Macie.1': macie_1.createControlRunbook,
};

export class ControlRunbooks extends Construct {
  protected readonly standardLongName: string;
  protected readonly standardVersion: string;
  protected controls: Set<string> = new Set<string>();

  constructor(scope: Construct, id: string, props: PlaybookProps) {
    super(scope, id);

    this.standardLongName = props.standardLongName;
    this.standardVersion = props.standardVersion;

    for (const remediation of props.remediations) {
      const controlId = remediation.control;

      if (remediation.executes) continue; // Skip remediations that map to other controls
      this.add(controlRunbooksRecord[controlId](this, controlId, props));
    }
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

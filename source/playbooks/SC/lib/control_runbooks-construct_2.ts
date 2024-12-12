// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../ssmdocs/control_runbook';
import { CfnCondition, CfnParameter, Fn } from 'aws-cdk-lib';

import * as cloudfront_1 from '../ssmdocs/SC_CloudFront.1';
import * as cloudfront_12 from '../ssmdocs/SC_CloudFront.12';
import * as codebuild_5 from '../ssmdocs/SC_CodeBuild.5';
import * as ec2_4 from '../ssmdocs/SC_EC2.4';
import * as ec2_8 from '../ssmdocs/SC_EC2.8';
import * as ec2_18 from '../ssmdocs/SC_EC2.18';
import * as ec2_19 from '../ssmdocs/SC_EC2.19';
import * as ec2_23 from '../ssmdocs/SC_EC2.23';
import * as ecr_1 from '../ssmdocs/SC_ECR.1';
import * as s3_11 from '../ssmdocs/SC_S3.11';
import * as s3_13 from '../ssmdocs/SC_S3.13';
import * as secretsmanager_1 from '../ssmdocs/SC_SecretsManager.1';
import * as secretsmanager_3 from '../ssmdocs/SC_SecretsManager.3';
import * as secretsmanager_4 from '../ssmdocs/SC_SecretsManager.4';
import * as ssm_4 from '../ssmdocs/SC_SSM.4';
import * as apigateway_3 from '../ssmdocs/SC_APIGateway.3';
import * as cloudfront_5 from '../ssmdocs/SC_CloudFront.5';
import * as cloudfront_2 from '../ssmdocs/SC_CloudFront.2';
import * as documentdb_2 from '../ssmdocs/SC_DocumentDB.2';
import * as dynamodb_2 from '../ssmdocs/SC_DynamoDB.2';
import * as dynamodb_1 from '../ssmdocs/SC_DynamoDB.1';
import * as eks_8 from '../ssmdocs/SC_EKS.8';
import * as elb_4 from '../ssmdocs/SC_ELB.4';
import * as elb_6 from '../ssmdocs/SC_ELB.6';
import * as neptune_2 from '../ssmdocs/SC_Neptune.2';
import * as neptune_5 from '../ssmdocs/SC_Neptune.5';
import * as neptune_4 from '../ssmdocs/SC_Neptune.4';
import * as rds_17 from '../ssmdocs/SC_RDS.17';
import * as rds_11 from '../ssmdocs/SC_RDS.11';
import * as s3_14 from '../ssmdocs/SC_S3.14';
import * as stepfunctions_1 from '../ssmdocs/SC_StepFunctions.1';
import * as waf_11 from '../ssmdocs/SC_WAF.11';

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
    this.add(apigateway_3.createControlRunbook(this, 'APIGateway.3', props));
    this.add(cloudfront_1.createControlRunbook(this, 'CloudFront.1', props));
    this.add(cloudfront_2.createControlRunbook(this, 'CloudFront.2', props));
    this.add(cloudfront_5.createControlRunbook(this, 'CloudFront.5', props));
    this.add(cloudfront_12.createControlRunbook(this, 'CloudFront.12', props));
    this.add(codebuild_5.createControlRunbook(this, 'CodeBuild.5', props));
    this.add(documentdb_2.createControlRunbook(this, 'DocumentDB.2', props));
    this.add(dynamodb_1.createControlRunbook(this, 'DynamoDB.1', props));
    this.add(dynamodb_2.createControlRunbook(this, 'DynamoDB.2', props));
    this.add(ec2_4.createControlRunbook(this, 'EC2.4', props));
    this.add(ec2_8.createControlRunbook(this, 'EC2.8', props));
    this.add(ec2_18.createControlRunbook(this, 'EC2.18', props));
    this.add(ec2_19.createControlRunbook(this, 'EC2.19', props));
    this.add(ec2_23.createControlRunbook(this, 'EC2.23', props));
    this.add(ecr_1.createControlRunbook(this, 'ECR.1', props));
    this.add(eks_8.createControlRunbook(this, 'EKS.8', props));
    this.add(elb_4.createControlRunbook(this, 'ELB.4', props));
    this.add(elb_6.createControlRunbook(this, 'ELB.6', props));
    this.add(neptune_2.createControlRunbook(this, 'Neptune.2', props));
    this.add(neptune_4.createControlRunbook(this, 'Neptune.4', props));
    this.add(neptune_5.createControlRunbook(this, 'Neptune.5', props));
    this.add(rds_11.createControlRunbook(this, 'RDS.11', props));
    this.add(rds_17.createControlRunbook(this, 'RDS.17', props));
    this.add(s3_11.createControlRunbook(this, 'S3.11', props));
    this.add(s3_13.createControlRunbook(this, 'S3.13', props));
    this.add(s3_14.createControlRunbook(this, 'S3.14', props));
    this.add(secretsmanager_1.createControlRunbook(this, 'SecretsManager.1', props));
    this.add(secretsmanager_3.createControlRunbook(this, 'SecretsManager.3', props));
    this.add(secretsmanager_4.createControlRunbook(this, 'SecretsManager.4', props));
    this.add(ssm_4.createControlRunbook(this, 'SSM.4', props));
    this.add(stepfunctions_1.createControlRunbook(this, 'StepFunctions.1', props));
    this.add(waf_11.createControlRunbook(this, 'WAF.11', props));
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

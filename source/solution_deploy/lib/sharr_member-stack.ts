#!/usr/bin/env node
/*****************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/
import * as cdk_nag from 'cdk-nag';
import * as cdk from '@aws-cdk/core';
import * as fs from 'fs';
import { AdminAccountParm } from '../../lib/admin_account_parm-construct';
import { StringParameter } from '@aws-cdk/aws-ssm';
import * as ssm from '@aws-cdk/aws-ssm';
import * as s3 from '@aws-cdk/aws-s3';
import { Key } from '@aws-cdk/aws-kms';
import {
  PolicyStatement,
  Effect,
  PolicyDocument,
  ServicePrincipal
} from '@aws-cdk/aws-iam';
import { RunbookFactory } from './runbook_factory';
import * as lambda from '@aws-cdk/aws-lambda';
import { RemovalPolicy } from '@aws-cdk/core';

export interface SolutionProps {
  description: string;
  solutionId: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionVersion: string;
  runtimePython: lambda.Runtime;
}

export class MemberStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: SolutionProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    const adminAccount = new AdminAccountParm(this, 'AdminAccountParameter', {
      solutionId: props.solutionId
    });

    //Create a new parameter to track Redshift.4 S3 bucket
    const createS3BucketForRedshift4 = new cdk.CfnParameter(this, 'CreateS3BucketForRedshiftAuditLogging', {
      description: "Create S3 Bucket For Redshift Cluster Audit Logging.",
      type: "String",
      allowedValues:["yes", "no"],
      default: "no"
    });

    const enableS3BucketForRedShift4 = new cdk.CfnCondition(this,
      "EnableS3BucketForRedShift4",
      {
        expression: cdk.Fn.conditionEquals(createS3BucketForRedshift4.valueAsString, 'yes')
      })

    //Create the S3 Bucket for Redshift.4

    const s3BucketForAuditLogging = new s3.Bucket(this, "S3BucketForRedShiftAuditLogging", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      publicReadAccess: false,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    })

    cdk_nag.NagSuppressions.addResourceSuppressions(s3BucketForAuditLogging, [
      {id: 'AwsSolutions-S1', reason: 'This is a logging bucket.'}
    ]);

    const bucketPolicy = new s3.BucketPolicy(this, 'S3BucketForRedShiftAuditLoggingBucketPolicy', {
      bucket: s3BucketForAuditLogging,
      removalPolicy: RemovalPolicy.RETAIN
    })
    bucketPolicy.document.addStatements(
      new PolicyStatement({
        sid: 'Put bucket policy needed for audit logging',
        effect: Effect.ALLOW,
        actions: [
          "s3:GetBucketAcl",
          "s3:PutObject"
        ],
        principals: [new ServicePrincipal('redshift.amazonaws.com')],
        resources: [
          s3BucketForAuditLogging.bucketArn,
          cdk.Fn.sub("arn:${AWS::Partition}:s3:::${BucketName}/*", {
            BucketName: `${s3BucketForAuditLogging.bucketName}`
          })
        ]
      })
    );
    const bucketPolicy_cfn_ref = bucketPolicy.node.defaultChild as s3.CfnBucketPolicy
    bucketPolicy_cfn_ref.cfnOptions.condition = enableS3BucketForRedShift4

    const s3BucketForAuditLogging_cfn_ref = s3BucketForAuditLogging.node.defaultChild as s3.CfnBucket
    s3BucketForAuditLogging_cfn_ref.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [{
          id: 'W35',
          reason: 'Logs bucket does not require logging configuration'
        }]
      }
    };

    cdk_nag.NagSuppressions.addResourceSuppressions(s3BucketForAuditLogging, [
      {id: 'AwsSolutions-S1', reason: 'Logs bucket does not require logging configuration'},
      {id: 'AwsSolutions-S10', reason: 'Secure transport requirement is redundant for this use case'}
    ]);
    cdk_nag.NagSuppressions.addResourceSuppressions(bucketPolicy, [
      {id: 'AwsSolutions-S10', reason: 'Secure transport requirement is redundant for this use case'}
    ]);

    s3BucketForAuditLogging_cfn_ref.cfnOptions.condition = enableS3BucketForRedShift4;

    bucketPolicy_cfn_ref.addDependsOn(s3BucketForAuditLogging_cfn_ref)

    //--------------------------
    // KMS Customer Managed Key

    // Key Policy
    const kmsKeyPolicy:PolicyDocument = new PolicyDocument();
    const kmsPerms:PolicyStatement = new PolicyStatement();
    kmsPerms.addActions(
        'kms:GenerateDataKey',
        'kms:GenerateDataKeyPair',
        'kms:GenerateDataKeyPairWithoutPlaintext',
        'kms:GenerateDataKeyWithoutPlaintext',
        'kms:Decrypt',
        'kms:Encrypt',
        'kms:ReEncryptFrom',
        'kms:ReEncryptTo',
        'kms:DescribeKey',
        'kms:DescribeCustomKeyStores'
    );
    kmsPerms.effect = Effect.ALLOW;
    kmsPerms.addResources("*"); // Only the key the policydocument is attached to
    kmsPerms.addPrincipals(new ServicePrincipal('sns.amazonaws.com'));
    kmsPerms.addPrincipals(new ServicePrincipal('s3.amazonaws.com'));
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.region}.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal(`cloudtrail.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal('cloudwatch.amazonaws.com'));
    kmsKeyPolicy.addStatements(kmsPerms);

    const kmsKey:Key = new Key(this, 'SHARR Remediation Key', {
      enableKeyRotation: true,
      alias: `${RESOURCE_PREFIX}-SHARR-Remediation-Key`,
      trustAccountIdentities: true,
      policy: kmsKeyPolicy
    });

    new StringParameter(this, 'SHARR Key Alias', {
      description: 'KMS Customer Managed Key that will encrypt data for remediations',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/CMK_REMEDIATION_ARN`,
      stringValue: kmsKey.keyArn
    });

    new StringParameter(this, 'SHARR Member Version', {
        description: 'Version of the AWS Security Hub Automated Response and Remediation solution',
        parameterName: `/Solutions/${RESOURCE_PREFIX}/member-version`,
        stringValue: props.solutionVersion
    });

    /********************
    ** Parameters
    ********************/

    const logGroupName = new cdk.CfnParameter(this, "LogGroupName", {
      type: "String",
      description: "Name of the log group to be used to create metric filters and cloudwatch alarms. You must use a Log Group that is the the logging destination of a multi-region CloudTrail"
    });

    /*********************************************
    ** Create SSM Parameter to store log group name
    *********************************************/
    new StringParameter(stack, 'SSMParameterLogGroupName', {
      description: 'Parameter to store log group name',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/Metrics_LogGroupName`,
      stringValue: logGroupName.valueAsString
    });

    /*********************************************
    ** Create SSM Parameter to store encryption key alias for the PCI.S3.4/AFSBP.S3.4
    *********************************************/
    new StringParameter(stack, 'SSMParameterForS3.4EncryptionKeyAlias', {
      description: 'Parameter to store encryption key alias for the PCI.S3.4/AFSBP.S3.4, replace the default value with the KMS Key Alias, other wise the remediation will enable the default AES256 encryption for the bucket.',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/afsbp/1.0.0/S3.4/KmsKeyAlias`,
      stringValue: 'default-s3-encryption'
    });

    /*********************************************
    ** Create SSM Parameter to store the S3 bucket name for AFSBP.REDSHIFT.4
    *********************************************/
    const ssmParameterForRedshift4BucketName = new StringParameter(stack, 'SSMParameterForS3BucketNameForREDSHIFT4', {
      description: 'Parameter to store the S3 bucket name for the remediation AFSBP.REDSHIFT.4, the default value is bucket-name which has to be updated by the user before using the remediation.',
      parameterName: `/Solutions/${props.solutionId}/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging`,
      stringValue: s3BucketForAuditLogging.bucketName
    });

    const ssmParameterForRedshift4BucketName_cfn_ref = ssmParameterForRedshift4BucketName.node.defaultChild as ssm.CfnParameter
    ssmParameterForRedshift4BucketName_cfn_ref.cfnOptions.condition = enableS3BucketForRedShift4

    ssmParameterForRedshift4BucketName_cfn_ref.addDependsOn(s3BucketForAuditLogging_cfn_ref)


    new cdk.CfnMapping(this, 'SourceCode', {
      mapping: { "General": {
        "S3Bucket": props.solutionDistBucket,
        "KeyPrefix": props.solutionTMN + '/' + props.solutionVersion
      }}
    });

    const runbookFactory = new RunbookFactory(this, 'RunbookProvider', {
      solutionId: props.solutionId,
      runtimePython: props.runtimePython,
      solutionDistBucket: props.solutionDistBucket,
      solutionTMN: props.solutionTMN,
      solutionVersion: props.solutionVersion,
      region: this.region,
      partition: this.partition
    });

    //-------------------------------------------------------------------------
    // Runbooks - shared automations
    //
    const runbookStack = new cdk.CfnStack(this, `RunbookStackNoRoles`, {
      templateUrl: "https://" + cdk.Fn.findInMap("SourceCode", "General", "S3Bucket") +
      "-reference.s3.amazonaws.com/" + cdk.Fn.findInMap("SourceCode", "General", "KeyPrefix") +
      "/aws-sharr-remediations.template"
    });

    runbookStack.node.addDependency(runbookFactory);

    //-------------------------------------------------------------------------
    // Loop through all of the Playbooks to create reference
    //
    const PB_DIR = `${__dirname}/../../playbooks`;
    const ignore = ['.DS_Store', 'common', '.pytest_cache', 'NEWPLAYBOOK', '.coverage'];
    const illegalChars = /[\._]/g;
    const listOfPlaybooks: string[] = [];
    fs.readdir(PB_DIR, (err, items) => {
      items.forEach((file) => {
        if (!ignore.includes(file)) {
          const templateFile = `${file}MemberStack.template`;
          //---------------------------------------------------------------------
          // Playbook Member Template Nested Stack
          //
          const parmname = file.replace(illegalChars, '');
          const memberStackOption = new cdk.CfnParameter(this, `LoadMemberStack${parmname}`, {
            type: "String",
            description: `Load Playbook member stack for ${file}?`,
            default: "yes",
            allowedValues: ["yes", "no"]
          });
          memberStackOption.overrideLogicalId(`Load${parmname}MemberStack`);
          listOfPlaybooks.push(memberStackOption.logicalId);

          const memberStack = new cdk.CfnStack(this, `PlaybookMemberStack${file}`, {
            parameters: {
              'SecHubAdminAccount': adminAccount.adminAccountNumber.valueAsString
            },
            templateUrl: "https://" + cdk.Fn.findInMap("SourceCode", "General", "S3Bucket") +
            "-reference.s3.amazonaws.com/" + cdk.Fn.findInMap("SourceCode", "General", "KeyPrefix") +
            "/playbooks/" + templateFile
          })

          memberStack.node.addDependency(runbookFactory);

          memberStack.cfnOptions.condition = new cdk.CfnCondition(this, `load${file}Cond`, {
            expression: cdk.Fn.conditionEquals(memberStackOption, "yes")
          });
        }
      });
    });
    /********************
    ** Metadata
    ********************/
    stack.templateOptions.metadata = {
      "AWS::CloudFormation::Interface": {
        ParameterGroups: [
          {
            Label: {default: "LogGroup Configuration"},
            Parameters: [logGroupName.logicalId]
          },
          {
            Label: {default: "Playbooks"},
            Parameters: listOfPlaybooks
          }
        ],
        ParameterLabels: {
          [logGroupName.logicalId]: {
            default: "Provide the name of the LogGroup to be used to create Metric Filters and Alarms",
          }
        }
      }
    };
  }
}

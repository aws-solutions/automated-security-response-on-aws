// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { readdirSync } from 'fs';
import {
  StackProps,
  Stack,
  App,
  CfnParameter,
  CfnCondition,
  Fn,
  CfnMapping,
  CfnStack,
  RemovalPolicy,
} from 'aws-cdk-lib';
import {
  PolicyStatement,
  Effect,
  PolicyDocument,
  ServicePrincipal,
  AccountRootPrincipal,
  StarPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import {
  Bucket,
  BucketEncryption,
  BlockPublicAccess,
  BucketPolicy,
  CfnBucketPolicy,
  CfnBucket,
} from 'aws-cdk-lib/aws-s3';
import { Key } from 'aws-cdk-lib/aws-kms';
import { CfnParameter as CfnSsmParameter, StringParameter } from 'aws-cdk-lib/aws-ssm';
import { NagSuppressions } from 'cdk-nag';
import AdminAccountParam from '../../lib/admin-account-param';
import { RunbookFactory } from './runbook_factory';

export interface SolutionProps extends StackProps {
  solutionId: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionVersion: string;
  runtimePython: Runtime;
}

export class MemberStack extends Stack {
  constructor(scope: App, id: string, props: SolutionProps) {
    super(scope, id, props);

    const adminAccountParam = new AdminAccountParam(this, 'AdminAccountParameter');

    //Create a new parameter to track Redshift.4 S3 bucket
    const createS3BucketForRedshift4 = new CfnParameter(this, 'CreateS3BucketForRedshiftAuditLogging', {
      description: 'Create S3 Bucket For Redshift Cluster Audit Logging.',
      type: 'String',
      allowedValues: ['yes', 'no'],
      default: 'no',
    });

    const enableS3BucketForRedShift4 = new CfnCondition(this, 'EnableS3BucketForRedShift4', {
      expression: Fn.conditionEquals(createS3BucketForRedshift4.valueAsString, 'yes'),
    });

    //Create the S3 Bucket for Redshift.4

    const s3BucketForAuditLogging = new Bucket(this, 'S3BucketForRedShiftAuditLogging', {
      encryption: BucketEncryption.S3_MANAGED,
      publicReadAccess: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    });

    NagSuppressions.addResourceSuppressions(s3BucketForAuditLogging, [
      { id: 'AwsSolutions-S1', reason: 'This is a logging bucket.' },
    ]);

    const bucketPolicy = new BucketPolicy(this, 'S3BucketForRedShiftAuditLoggingBucketPolicy', {
      bucket: s3BucketForAuditLogging,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    bucketPolicy.document.addStatements(
      new PolicyStatement({
        sid: 'Put bucket policy needed for audit logging',
        effect: Effect.ALLOW,
        actions: ['s3:GetBucketAcl', 's3:PutObject'],
        principals: [new ServicePrincipal('redshift.amazonaws.com')],
        resources: [
          s3BucketForAuditLogging.bucketArn,
          Fn.sub('arn:${AWS::Partition}:s3:::${BucketName}/*', {
            BucketName: `${s3BucketForAuditLogging.bucketName}`,
          }),
        ],
      }),
      new PolicyStatement({
        sid: 'EnforceSSL',
        effect: Effect.DENY,
        actions: ['s3:*'],
        principals: [new StarPrincipal()],
        resources: [s3BucketForAuditLogging.bucketArn, s3BucketForAuditLogging.arnForObjects('*')],
        conditions: { Bool: { ['aws:SecureTransport']: 'false' } },
      })
    );
    const bucketPolicy_cfn_ref = bucketPolicy.node.defaultChild as CfnBucketPolicy;
    bucketPolicy_cfn_ref.cfnOptions.condition = enableS3BucketForRedShift4;

    const s3BucketForAuditLogging_cfn_ref = s3BucketForAuditLogging.node.defaultChild as CfnBucket;
    s3BucketForAuditLogging_cfn_ref.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W35',
            reason: 'Logs bucket does not require logging configuration',
          },
        ],
      },
    };

    NagSuppressions.addResourceSuppressions(s3BucketForAuditLogging, [
      { id: 'AwsSolutions-S1', reason: 'Logs bucket does not require logging configuration' },
    ]);

    s3BucketForAuditLogging_cfn_ref.cfnOptions.condition = enableS3BucketForRedShift4;

    bucketPolicy_cfn_ref.addDependency(s3BucketForAuditLogging_cfn_ref);

    //--------------------------
    // KMS Customer Managed Key

    const stack = Stack.of(this);
    // Key Policy
    const kmsKeyPolicy: PolicyDocument = new PolicyDocument();
    const kmsPerms: PolicyStatement = new PolicyStatement();
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
    kmsPerms.addResources('*'); // Only the key the policydocument is attached to
    kmsPerms.addPrincipals(new ServicePrincipal('sns.amazonaws.com'));
    kmsPerms.addPrincipals(new ServicePrincipal('s3.amazonaws.com'));
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.region}.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal(`cloudtrail.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal('cloudwatch.amazonaws.com'));
    kmsKeyPolicy.addStatements(kmsPerms);

    const kmsRootPolicy = new PolicyStatement({
      principals: [new AccountRootPrincipal()],
      actions: ['kms:*'],
      resources: ['*'],
    });
    kmsKeyPolicy.addStatements(kmsRootPolicy);

    const kmsKey: Key = new Key(this, 'SHARR Remediation Key', {
      enableKeyRotation: true,
      alias: `${props.solutionId}-SHARR-Remediation-Key`,
      policy: kmsKeyPolicy,
    });

    new StringParameter(this, 'SHARR Key Alias', {
      description: 'KMS Customer Managed Key that will encrypt data for remediations',
      parameterName: `/Solutions/${props.solutionId}/CMK_REMEDIATION_ARN`,
      stringValue: kmsKey.keyArn,
    });

    new StringParameter(this, 'SHARR Member Version', {
      description: 'Version of the AWS Security Hub Automated Response and Remediation solution',
      parameterName: `/Solutions/${props.solutionId}/member-version`,
      stringValue: props.solutionVersion,
    });

    /********************
     ** Parameters
     ********************/

    const logGroupName = new CfnParameter(this, 'LogGroupName', {
      type: 'String',
      description:
        'Name of the log group to be used to create metric filters and cloudwatch alarms. You must use a Log Group that is the the logging destination of a multi-region CloudTrail',
    });

    /*********************************************
     ** Create SSM Parameter to store log group name
     *********************************************/
    new StringParameter(stack, 'SSMParameterLogGroupName', {
      description: 'Parameter to store log group name',
      parameterName: `/Solutions/${props.solutionId}/Metrics_LogGroupName`,
      stringValue: logGroupName.valueAsString,
    });

    /*********************************************
     ** Create SSM Parameter to store encryption key alias for the PCI.S3.4/AFSBP.S3.4
     *********************************************/
    new StringParameter(stack, 'SSMParameterForS3.4EncryptionKeyAlias', {
      description:
        'Parameter to store encryption key alias for the PCI.S3.4/AFSBP.S3.4, replace the default value with the KMS Key Alias, other wise the remediation will enable the default AES256 encryption for the bucket.',
      parameterName: `/Solutions/${props.solutionId}/afsbp/1.0.0/S3.4/KmsKeyAlias`,
      stringValue: 'default-s3-encryption',
    });

    /*********************************************
     ** Create SSM Parameter to store the S3 bucket name for AFSBP.REDSHIFT.4
     *********************************************/
    const ssmParameterForRedshift4BucketName = new StringParameter(stack, 'SSMParameterForS3BucketNameForREDSHIFT4', {
      description:
        'Parameter to store the S3 bucket name for the remediation AFSBP.REDSHIFT.4, the default value is bucket-name which has to be updated by the user before using the remediation.',
      parameterName: `/Solutions/${props.solutionId}/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging`,
      stringValue: s3BucketForAuditLogging.bucketName,
    });

    const ssmParameterForRedshift4BucketName_cfn_ref = ssmParameterForRedshift4BucketName.node
      .defaultChild as CfnSsmParameter;
    ssmParameterForRedshift4BucketName_cfn_ref.cfnOptions.condition = enableS3BucketForRedShift4;

    ssmParameterForRedshift4BucketName_cfn_ref.addDependency(s3BucketForAuditLogging_cfn_ref);

    new CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionTMN + '/' + props.solutionVersion,
        },
      },
    });

    const runbookFactory = new RunbookFactory(this, 'RunbookProvider');

    //-------------------------------------------------------------------------
    // Runbooks - shared automations
    //
    const runbookStack = new CfnStack(this, `RunbookStackNoRoles`, {
      templateUrl:
        'https://' +
        Fn.findInMap('SourceCode', 'General', 'S3Bucket') +
        '-reference.s3.amazonaws.com/' +
        Fn.findInMap('SourceCode', 'General', 'KeyPrefix') +
        '/aws-sharr-remediations.template',
    });

    runbookStack.node.addDependency(runbookFactory);

    //-------------------------------------------------------------------------
    // Loop through all of the Playbooks to create reference
    //
    const PB_DIR = `${__dirname}/../../playbooks`;
    const ignore = ['.DS_Store', 'common', '.pytest_cache', 'NEWPLAYBOOK', '.coverage'];
    const illegalChars = /[\\._]/g;
    const listOfPlaybooks: string[] = [];
    const items = readdirSync(PB_DIR);
    items.forEach((file) => {
      if (!ignore.includes(file)) {
        const templateFile = `${file}MemberStack.template`;
        //---------------------------------------------------------------------
        // Playbook Member Template Nested Stack
        //
        const parmname = file.replace(illegalChars, '');
        const memberStackOption = new CfnParameter(this, `LoadMemberStack${parmname}`, {
          type: 'String',
          description: `Load Playbook member stack for ${file}?`,
          default: 'yes',
          allowedValues: ['yes', 'no'],
        });
        memberStackOption.overrideLogicalId(`Load${parmname}MemberStack`);
        listOfPlaybooks.push(memberStackOption.logicalId);

        const memberStack = new CfnStack(this, `PlaybookMemberStack${file}`, {
          parameters: {
            SecHubAdminAccount: adminAccountParam.value,
          },
          templateUrl:
            'https://' +
            Fn.findInMap('SourceCode', 'General', 'S3Bucket') +
            '-reference.s3.amazonaws.com/' +
            Fn.findInMap('SourceCode', 'General', 'KeyPrefix') +
            '/playbooks/' +
            templateFile,
        });

        memberStack.node.addDependency(runbookFactory);

        memberStack.cfnOptions.condition = new CfnCondition(this, `load${file}Cond`, {
          expression: Fn.conditionEquals(memberStackOption, 'yes'),
        });
      }
    });

    /********************
     ** Metadata
     ********************/
    stack.templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'LogGroup Configuration' },
            Parameters: [logGroupName.logicalId],
          },
          {
            Label: { default: 'Playbooks' },
            Parameters: listOfPlaybooks,
          },
        ],
        ParameterLabels: {
          [logGroupName.logicalId]: {
            default: 'Provide the name of the LogGroup to be used to create Metric Filters and Alarms',
          },
        },
      },
    };
  }
}

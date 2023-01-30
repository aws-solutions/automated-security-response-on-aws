// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { readdirSync } from 'fs';
import { StackProps, Stack, App, CfnParameter, CfnCondition, Fn, CfnMapping, CfnStack } from 'aws-cdk-lib';
import { PolicyStatement, Effect, PolicyDocument, ServicePrincipal, AccountRootPrincipal } from 'aws-cdk-lib/aws-iam';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Key } from 'aws-cdk-lib/aws-kms';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import AdminAccountParam from '../../lib/admin-account-param';
import { RunbookFactory } from './runbook_factory';
import { RedshiftAuditLogging } from './redshift-audit-logging';

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

    new RedshiftAuditLogging(this, 'RedshiftAuditLogging', { solutionId: props.solutionId });

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

#!/usr/bin/env node
/******************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.        *
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

import { IssmPlaybookProps, RemediationRunbookProps } from '../../lib/ssmplaybook';
import * as cdk_nag from 'cdk-nag';
import * as lambda from '@aws-cdk/aws-lambda';
import * as s3 from '@aws-cdk/aws-s3';
import * as iam from '@aws-cdk/aws-iam';
import * as cdk from '@aws-cdk/core';
import * as fs from 'fs';

export interface RunbookFactoryProps {
  solutionId: string;
  runtimePython: lambda.Runtime;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionVersion: string;
  region: string;
  partition: string;
};

export class RunbookFactory extends cdk.Construct {
  constructor(scope: cdk.Construct, id: string, props: RunbookFactoryProps) {
    super(scope, id);

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, '');

    const policy = new iam.Policy(this, 'Policy', {
      policyName: RESOURCE_PREFIX + '-SHARR_Runbook_Provider_Policy',
      statements: [
        new iam.PolicyStatement({
          actions: [
            'cloudwatch:PutMetricData'
          ],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          actions: [
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents'
          ],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          actions: [
            'ssm:CreateDocument',
            'ssm:UpdateDocument',
            'ssm:UpdateDocumentDefaultVersion',
            'ssm:ListDocumentVersions',
            'ssm:DeleteDocument'
          ],
          resources: ['*']
        })
      ]
    });

    const cfnPolicy = policy.node.defaultChild as iam.CfnPolicy;
    cfnPolicy.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W12',
            reason: 'Resource * is required in order to manage arbitrary SSM documents'
          }
        ]
      }
    };

    cdk_nag.NagSuppressions.addResourceSuppressions(policy, [
      {id: 'AwsSolutions-IAM5', reason: 'Resource * is required in order to manage arbitrary SSM documents'}
    ]);

    const role = new iam.Role(this, 'Role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to allow creation of updatable SSM documents'
    });

    role.attachInlinePolicy(policy);

    const SolutionsBucket = s3.Bucket.fromBucketAttributes(this, 'SolutionsBucket', {
      bucketName: props.solutionDistBucket + '-' + props.region
    });

    const memberLambdaLayer = new lambda.LayerVersion(this, 'MemberLambdaLayer', {
      compatibleRuntimes: [props.runtimePython],
      description: 'SO0111 SHARR Common functions used by the solution member stack',
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      code: lambda.Code.fromBucket(
          SolutionsBucket,
          props.solutionTMN + '/' + props.solutionVersion + '/lambda/memberLayer.zip'
      )
    });

    const lambdaFunction = new lambda.Function(this, 'Function', {
      functionName: RunbookFactory.getLambdaFunctionName(props.solutionId),
      handler: 'updatableRunbookProvider.lambda_handler',
      runtime: props.runtimePython,
      description: 'Custom resource to manage versioned SSM documents',
      code: lambda.Code.fromBucket(
          SolutionsBucket,
          props.solutionTMN + '/' + props.solutionVersion + '/lambda/updatableRunbookProvider.py.zip'
      ),
      environment: {
        LOG_LEVEL: 'info',
        SOLUTION_ID: `AwsSolution/${props.solutionId}/${props.solutionVersion}`
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: role,
      layers: [memberLambdaLayer],
      reservedConcurrentExecutions: 1
    });

    const cfnLambdaFunction = lambdaFunction.node.defaultChild as lambda.CfnFunction;
    cfnLambdaFunction.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W58',
            reason: 'False positive. Access is provided via a policy'
          },
          {
            id: 'W89',
            reason: 'There is no need to run this lambda in a VPC'
          }
        ]
      }
    };
  }

  static getLambdaFunctionName(solutionId: string): string {
    const RESOURCE_PREFIX = solutionId.replace(/^DEV-/, '');
    return `${RESOURCE_PREFIX}-SHARR-updatableRunbookProvider`;
  }

  static getServiceToken(scope: cdk.Construct, solutionId: string): string {
    const stack = cdk.Stack.of(scope);
    return `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${RunbookFactory.getLambdaFunctionName(solutionId)}`;
  }

  static getResourceType(): string {
    return 'Custom::UpdatableRunbook';
  }

  static createControlRunbook(scope: cdk.Construct, id: string, props: IssmPlaybookProps): cdk.CustomResource {
    let scriptPath = '';
    if (props.scriptPath == undefined ) {
      scriptPath = `${props.ssmDocPath}/scripts`;
    } else {
      scriptPath = props.scriptPath;
    }

    let commonScripts = '';
    if (props.commonScripts == undefined ) {
      commonScripts = '../common';
    } else {
      commonScripts = props.commonScripts;
    }

    const enableParam = new cdk.CfnParameter(scope, 'Enable ' + props.controlId, {
      type: 'String',
      description: `Enable/disable availability of remediation for ${props.securityStandard} version ${props.securityStandardVersion} Control ${props.controlId} in Security Hub Console Custom Actions. If NOT Available the remediation cannot be triggered from the Security Hub console in the Security Hub Admin account.`,
      default: 'Available',
      allowedValues: ['Available', 'NOT Available']
    });

    const installSsmDoc = new cdk.CfnCondition(scope, 'Enable ' + props.controlId + ' Condition', {
      expression: cdk.Fn.conditionEquals(enableParam, 'Available')
    });

    const ssmDocName = `SHARR-${props.securityStandard}_${props.securityStandardVersion}_${props.controlId}`;
    const ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`;
    const ssmDocType = props.ssmDocFileName.substring(props.ssmDocFileName.length - 4).toLowerCase();

    const ssmDocIn = fs.readFileSync(ssmDocFQFileName, 'utf8');

    let ssmDocOut: string = '';
    const re = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/;

    for (const line of ssmDocIn.split('\n')) {
      const foundMatch = re.exec(line);
      if (foundMatch && foundMatch.groups && foundMatch.groups.script) {
        let pathAndFileToInsert = foundMatch.groups.script;
        // If a relative path is provided then use it
        if (pathAndFileToInsert.substring(0, 7) === 'common/') {
          pathAndFileToInsert = `${commonScripts}/${pathAndFileToInsert.substring(7)}`;
        } else {
          pathAndFileToInsert = `${scriptPath}/${pathAndFileToInsert}`;
        }
        const scriptIn = fs.readFileSync(pathAndFileToInsert, 'utf8');
        for (const scriptLine of scriptIn.split('\n')) {
          ssmDocOut += foundMatch.groups.padding + scriptLine + '\n';
        }
      } else {
        ssmDocOut += line + '\n';
      }
    }

    const ssmDoc = new cdk.CustomResource(scope, id, {
      serviceToken: RunbookFactory.getServiceToken(scope, props.solutionId),
      resourceType: RunbookFactory.getResourceType(),
      properties: {
        Name: ssmDocName,
        Content: ssmDocOut,
        DocumentFormat: ssmDocType.toUpperCase(),
        VersionName: props.solutionVersion,
        DocumentType: 'Automation'
      }
    });

    const ssmDocCfnResource = ssmDoc.node.defaultChild as cdk.CfnCustomResource;
    ssmDocCfnResource.cfnOptions.condition = installSsmDoc;

    return ssmDoc;
  }

  static createRemediationRunbook(scope: cdk.Construct, id: string, props: RemediationRunbookProps) {
    const ssmDocName = `SHARR-${props.ssmDocName}`;
    let scriptPath = '';
    if (props.scriptPath == undefined) {
      scriptPath = 'ssmdocs/scripts';
    } else {
      scriptPath = props.scriptPath;
    }

    const ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`;
    const ssmDocType = props.ssmDocFileName.substring(props.ssmDocFileName.length - 4).toLowerCase();

    const ssmDocIn = fs.readFileSync(ssmDocFQFileName, 'utf8');

    let ssmDocOut: string = '';
    const re = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/;

    for (const line of ssmDocIn.split('\n')) {
      const foundMatch = re.exec(line);
      if (foundMatch && foundMatch.groups && foundMatch.groups.script) {
        const scriptIn = fs.readFileSync(`${scriptPath}/${foundMatch.groups.script}`, 'utf8');
        for (const scriptLine of scriptIn.split('\n')) {
          ssmDocOut += foundMatch.groups.padding + scriptLine + '\n';
        }
      } else {
        ssmDocOut += line + '\n';
      }
    }

    const runbook = new cdk.CustomResource(scope, id, {
      serviceToken: RunbookFactory.getServiceToken(scope, props.solutionId),
      resourceType: RunbookFactory.getResourceType(),
      properties: {
        Name: ssmDocName,
        Content: ssmDocOut,
        DocumentFormat: ssmDocType.toUpperCase(),
        DocumentType: 'Automation'
      }
    });

    return runbook;
  }
};

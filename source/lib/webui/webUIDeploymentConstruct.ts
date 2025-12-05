// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CustomResource, Duration, Fn, Stack } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Runtime } from 'aws-cdk-lib/aws-lambda';

import * as s3 from 'aws-cdk-lib/aws-s3';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';

export interface UICustomResourceConstructProps {
  readonly apiEndpoint: string;
  readonly awsRegion: string;
  readonly userPoolId: string;
  readonly userPoolClientId: string;
  readonly oauthDomain: string;
  readonly distributionDomainName: string;
  readonly solutionTMN: string;
  readonly sourceCodeBucket: s3.IBucket;
  readonly destinationCodeBucket: IBucket;
  readonly uiBucket: IBucket;
  readonly solutionVersion: string;
  readonly stackId: string;
  readonly ticketingGenFunction: string;
}

export class WebUIDeploymentConstruct extends Construct {
  constructor(scope: Construct, id: string, props: UICustomResourceConstructProps) {
    super(scope, id);
    const stack = Stack.of(this);

    // Create condition to check if ticketing function ARN is provided
    const ticketingEnabledCondition = new CfnCondition(this, 'TicketingEnabledCondition', {
      expression: Fn.conditionNot(Fn.conditionEquals(props.ticketingGenFunction, '')),
    });

    const webUIConfig = {
      API: {
        endpoints: [
          {
            name: 'ASRApi',
            endpoint: props.apiEndpoint,
          },
        ],
      },
      loggingLevel: 'INFO',
      Auth: {
        region: props.awsRegion,
        userPoolId: props.userPoolId,
        userPoolWebClientId: props.userPoolClientId,
        mandatorySignIn: true,
        oauth: {
          domain: props.oauthDomain,
          scope: ['openid', 'profile', 'email', 'aws.cognito.signin.user.admin', 'asr-api/api'],
          redirectSignIn: `https://${props.distributionDomainName}/callback`,
          redirectSignOut: `https://${props.distributionDomainName}`,
          responseType: 'code',
          clientId: props.userPoolClientId,
        },
      },
      ticketingEnabled: Fn.conditionIf(ticketingEnabledCondition.logicalId, 'true', 'false').toString(),
    };
    const webUiDeploymentConfig = {
      SrcBucket: props.sourceCodeBucket.bucketName,
      SrcPath: `${props.solutionTMN}/${props.solutionVersion}/webui/`, // Path within the SrcBucket that holds the files to copy
      WebUIBucket: props.uiBucket.bucketName,
      awsExports: webUIConfig,
    };

    const uiCopyAssetsFn = new lambda.Function(this, 'DeployWebUI', {
      runtime: Runtime.NODEJS_22_X,
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      handler: 'api/handlers/deployWebui.lambdaHandler',
      timeout: Duration.minutes(4),
      environment: {
        LOG_LEVEL: 'INFO',
        CONFIG: JSON.stringify(webUiDeploymentConfig),
        POWERTOOLS_SERVICE_NAME: 'DeployWebUI',
        SOLUTION_VERSION: props.solutionVersion,
        STACK_ID: props.stackId,
        AWS_ACCOUNT_ID: stack.account,
      },
    });
    props.sourceCodeBucket.grantRead(uiCopyAssetsFn);
    props.uiBucket.grantPut(uiCopyAssetsFn);

    addCfnGuardSuppression(uiCopyAssetsFn, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(uiCopyAssetsFn, 'LAMBDA_CONCURRENCY_CHECK');

    new CustomResource(this, 'WebUIDeploymentResource', {
      serviceToken: uiCopyAssetsFn.functionArn,
      properties: {
        SolutionVersion: props.solutionVersion,
        // Force CustomResource to update when UI code changes
        DeploymentTimestamp: Date.now().toString(),
        TicketingGenFunction: props.ticketingGenFunction,
      },
      // if custom resource didn't respond after 4 minutes, something went wrong. no need to wait 60 minutes
      serviceTimeout: Duration.minutes(5),
    });
  }
}

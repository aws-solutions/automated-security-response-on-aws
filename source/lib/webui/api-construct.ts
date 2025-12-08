// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { wrapManagedRuleSet } from '@aws-solutions-constructs/core';
import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Table } from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';

export interface ApiConstructProps {
  solutionId: string;
  solutionVersion: string;
  solutionTMN: string;
  solutionsBucket: s3.IBucket;
  resourceNamePrefix: string;
  findingsTable: string;
  remediationHistoryTable: string;
  userAccountMappingTable: Table;
  functionName: string;
  kmsKeyARN: string;
  authorizer?: apigateway.CognitoUserPoolsAuthorizer;
  userPoolId?: string;
  orchestratorArn: string;
  distributionDomainName: string;
  csvExportBucket: s3.IBucket;
  presignedUrlTTLDays: number;
  securityHubV2Enabled: string;
}

export class ApiConstruct extends Construct {
  public readonly api: apigateway.RestApi;
  public readonly apiLambda: lambda.Function;

  constructor(scope: Construct, id: string, props: ApiConstructProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);

    this.apiLambda = new lambda.Function(this, 'APILambda', {
      runtime: lambda.Runtime.NODEJS_22_X,
      functionName: props.functionName,
      handler: 'api/handlers/apiHandler.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      description: 'ASR API Lambda function',
      environment: {
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_LOG_LEVEL: 'INFO',
        USER_POOL_ID: props.userPoolId ?? '',
        USER_ACCOUNT_MAPPING_TABLE_NAME: props.userAccountMappingTable.tableName,
        FINDINGS_TABLE_NAME: cdk.Fn.select(1, cdk.Fn.split('/', props.findingsTable)),
        REMEDIATION_HISTORY_TABLE_NAME: cdk.Fn.select(1, cdk.Fn.split('/', props.remediationHistoryTable)),
        CSV_EXPORT_BUCKET_NAME: props.csvExportBucket.bucketName,
        PRESIGNED_URL_TTL_DAYS: props.presignedUrlTTLDays.toString(),
        ORCHESTRATOR_ARN: props.orchestratorArn,
        WEB_UI_URL: `https://${props.distributionDomainName}`,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
        SECURITY_HUB_V2_ENABLED: props.securityHubV2Enabled,
        EXPORT_MAX_TIME_MS: process.env.EXPORT_MAX_TIME_MS || '26000', // API Gateway has 29s hard limit; 26s for export + 3s buffer
        EXPORT_MAX_RECORDS: process.env.EXPORT_MAX_RECORDS || '50000', // Memory safety limit
      },
      memorySize: 512,
      timeout: cdk.Duration.seconds(29), // Match API Gateway timeout (29s hard limit)
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant DynamoDB table read and write permissions to API Lambda
    const findingsTable = dynamodb.Table.fromTableArn(this, 'FindingsTable', props.findingsTable);
    findingsTable.grantReadWriteData(this.apiLambda);

    const remediationHistoryTable = dynamodb.Table.fromTableArn(
      this,
      'RemediationHistoryTable',
      props.remediationHistoryTable,
    );
    remediationHistoryTable.grantReadWriteData(this.apiLambda);

    // Grant additional permissions for GSI queries
    this.apiLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:Query'],
        resources: [`${props.findingsTable}/index/*`],
      }),
    );

    // Grant permissions for remediation history table GSI queries
    this.apiLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:Query'],
        resources: [`${props.remediationHistoryTable}/index/*`],
      }),
    );

    props.userAccountMappingTable.grantReadWriteData(this.apiLambda);

    // Grant permissions to access solution's parameters
    this.apiLambda.addToRolePolicy(
      new PolicyStatement({
        actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter', 'ssm:DeleteParameter'],
        resources: [`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`],
      }),
    );

    // Add Cognito permissions for authorization and user management
    if (props.userPoolId) {
      this.apiLambda.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'cognito-idp:GetUser',
            'cognito-idp:AdminListGroupsForUser',
            'cognito-idp:AdminGetUser',
            'cognito-idp:ListUsers',
            'cognito-idp:AdminCreateUser',
            'cognito-idp:AdminAddUserToGroup',
            'cognito-idp:AdminDeleteUser',
          ],
          resources: [
            `arn:${stack.partition}:cognito-idp:${stack.region}:${stack.account}:userpool/${props.userPoolId}`,
          ],
        }),
      );
    }

    // Grant KMS permissions for DynamoDB encryption/decryption
    this.apiLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['kms:Decrypt', 'kms:DescribeKey'],
        resources: [props.kmsKeyARN],
      }),
    );

    this.apiLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['states:StartExecution'],
        resources: [props.orchestratorArn],
      }),
    );

    this.apiLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['s3:PutObject', 's3:GetObject'],
        resources: [`${props.csvExportBucket.bucketArn}/*`],
      }),
    );

    // Add CFN Guard suppressions for Lambda
    const lambdaResource = this.apiLambda.node.findChild('Resource') as lambda.CfnFunction;
    lambdaResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W58',
            reason: 'Lambda function has CloudWatch Logs permissions via attached policy.',
          },
          {
            id: 'W89',
            reason: 'This Lambda function does not need to access VPC resources.',
          },
          {
            id: 'W92',
            reason: 'Reserved concurrency is not required for this use case.',
          },
        ],
      },
    };

    addCfnGuardSuppression(this.apiLambda, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.apiLambda, 'LAMBDA_CONCURRENCY_CHECK');

    const apiLogGroup = new logs.LogGroup(this, 'AsrApiLogGroup', {
      retention: logs.RetentionDays.TEN_YEARS,
    });

    addCfnGuardSuppression(apiLogGroup, 'CLOUDWATCH_LOG_GROUP_ENCRYPTED');

    const allowHeaders = [
      'Content-Type',
      'X-Amz-Date',
      'Authorization',
      'X-Api-Key',
      'X-Amz-Security-Token',
      'X-Amz-User-Agent',
    ];
    this.api = new apigateway.RestApi(this, 'AutomatedSecurityResponseApi', {
      restApiName: `AutomatedSecurityResponseApi`,
      description: 'Automated Security Response on AWS solution APIs',
      deployOptions: {
        stageName: 'prod',
        dataTraceEnabled: false,
        metricsEnabled: true,
        accessLogDestination: new apigateway.LogGroupLogDestination(apiLogGroup),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields(),
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowCredentials: false,
        allowHeaders: allowHeaders,
      },
    });

    // Configure authorization options
    const authorizationOptions: any = {
      apiKeyRequired: false,
    };

    if (props.authorizer) {
      authorizationOptions.authorizationType = apigateway.AuthorizationType.COGNITO;
      authorizationOptions.authorizer = props.authorizer;
      authorizationOptions.authorizationScopes = ['asr-api/api'];
    }

    // Add CORS headers to responses generated by API Gateway itself
    const responseHeaders = {
      'gatewayresponse.header.Access-Control-Allow-Origin': "'*'",
      'gatewayresponse.header.Access-Control-Allow-Headers':
        "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent'",
      'gatewayresponse.header.Access-Control-Allow-Methods': "'GET,OPTIONS,POST,PUT,DELETE'",
    };

    // Create a proxy resource with {proxy+} to catch all paths
    const proxyResource = this.api.root.addResource('{proxy+}', {
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowCredentials: false,
        allowHeaders: allowHeaders,
      },
    });

    // Add a method that catches any HTTP method; routing is handled in the Lambda Function itself
    const lambdaIntegration = new apigateway.LambdaIntegration(this.apiLambda, {});
    proxyResource.addMethod('ANY', lambdaIntegration, authorizationOptions);

    // Add CORS headers to 4xx and 5xx responses from API Gateway
    new apigateway.GatewayResponse(this, 'CORSResponse4xx', {
      restApi: this.api,
      type: apigateway.ResponseType.DEFAULT_4XX,
      responseHeaders: responseHeaders,
    });

    new apigateway.GatewayResponse(this, 'CORSResponse5xx', {
      restApi: this.api,
      type: apigateway.ResponseType.DEFAULT_5XX,
      responseHeaders: responseHeaders,
    });

    // Add CFN Guard suppressions for API Gateway
    const apiResource = this.api.node.findChild('Resource') as apigateway.CfnRestApi;
    apiResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W59',
            reason: 'API Gateway is configured with CloudWatch logging and X-Ray tracing.',
          },
        ],
      },
    };

    addCfnGuardSuppression(this.api.deploymentStage, 'API_GW_CACHE_ENABLED_AND_ENCRYPTED');

    // WAF Web ACL
    const cfnWebACL = new wafv2.CfnWebACL(this, 'WebACL', {
      name: `${props.resourceNamePrefix}-ASR-WebACL`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      description: 'WAF for Automated Security Response on AWS solution',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `${props.resourceNamePrefix}ASRWebAclMetrics`,
        sampledRequestsEnabled: true,
      },
      rules: [
        wrapManagedRuleSet('AWSManagedRulesBotControlRuleSet', 'AWS', 1),
        wrapManagedRuleSet('AWSManagedRulesKnownBadInputsRuleSet', 'AWS', 2),
        wrapManagedRuleSet('AWSManagedRulesCommonRuleSet', 'AWS', 3),
        wrapManagedRuleSet('AWSManagedRulesAnonymousIpList', 'AWS', 4),
        wrapManagedRuleSet('AWSManagedRulesAmazonIpReputationList', 'AWS', 5),
        wrapManagedRuleSet('AWSManagedRulesAdminProtectionRuleSet', 'AWS', 6),
        wrapManagedRuleSet('AWSManagedRulesSQLiRuleSet', 'AWS', 7),
      ],
    });

    // Associate WAF with API Gateway
    new wafv2.CfnWebACLAssociation(this, 'WebACLAssociation', {
      resourceArn: this.api.deploymentStage.stageArn,
      webAclArn: cfnWebACL.attrArn,
    });
  }
}

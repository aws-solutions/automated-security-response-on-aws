// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import { Construct } from 'constructs';
import { ApiConstruct } from './webui/api-construct';
import { CognitoConstruct } from './webui/cognito-construct';
import { WebUIDeploymentConstruct } from './webui/webUIDeploymentConstruct';
import { WebUIHostingConstruct } from './webui/webUIHostingConstruct';
import { Key } from 'aws-cdk-lib/aws-kms';
import { getConfig } from './config/cdk-config';
import { applyConditionToSubtree } from './cdk-helper/apply-condition-to-subtree';

export interface WebUINestedStackProps extends cdk.NestedStackProps {
  solutionId: string;
  solutionVersion: string;
  solutionTMN: string;
  solutionsBucket: s3.IBucket;
  resourceNamePrefix: string;
  findingsTable: string;
  remediationHistoryTable: string;
  remediationConfigTable: dynamodb.Table;
  resourceFiltersTable: dynamodb.Table;
  apiFunctionName: string;
  stackName: string;
  kmsKeyARN: string;
  adminUserEmail: string;
  orchestratorArn: string;
  csvExportBucket: s3.IBucket;
  presignedUrlTTLDays: number;
  ticketingGenFunction: string;
  securityHubV2Enabled: string;
  notificationConfigTable: dynamodb.Table;
  notificationBatchesTable: dynamodb.Table;
  iacTemplatesBucket: s3.IBucket;
  customRunbookTable: dynamodb.Table;
  customRunbookBucket: s3.IBucket;
  enableRollback: string;
  findingsTtlDays: string;
  mfaConfiguration: string;
  /**
   * 'yes'/'no' — whether the Web UI frontend is deployed. The frontend (CloudFront UI,
   * WebUIDeployment, API Gateway stage, and the API's Cognito authorizer) is gated on
   * this. Shared core services (Cognito user pool, API Lambda, user/account mapping
   * table) deploy regardless, so an MCP-only deployment still gets them.
   */
  deployFrontend: string;
  /** 'yes'/'no' — whether the MCP grant endpoints are enabled (gated on EnableMcpServer). */
  mcpEnabled: string;
}

export class WebUINestedStack extends cdk.NestedStack {
  public readonly api: apigateway.RestApi;
  public readonly webUIBucket: s3.Bucket;
  public readonly distributionDomainName: string;
  public readonly distributionDomainNameOutputLogicalId: string;
  public readonly apiEndpointOutputLogicalId: string;
  public readonly userPoolId: string;
  public readonly userPoolClientId: string;
  public readonly userPoolDomain: string;
  public readonly userAccountMappingTableARN: string;
  public readonly userAccountMappingTableName: string;
  public readonly adminSecurityNotificationsTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: WebUINestedStackProps) {
    super(scope, id, props);

    const config = getConfig();

    this.templateOptions.description = `(${props.solutionId}W) - Automated Security Response on AWS - WebUI nested stack for hosting the web user interface and API components. ${props.solutionVersion}`;

    // Gates the frontend-only resources. The nested stack itself deploys on
    // coreServicesEnabled (Web UI OR AgentCore Gateway) in the parent, but the browser
    // frontend — CloudFront UI, its deployment, the API Gateway stage, and the API's
    // Cognito authorizer — is only created when the Web UI is on. Cognito, the API
    // Lambda, and the mapping table stay unconditional as shared core services.
    const frontendEnabled = new cdk.CfnCondition(this, 'frontendEnabled', {
      expression: cdk.Fn.conditionEquals(props.deployFrontend, 'yes'),
    });

    const uiConstruct = new WebUIHostingConstruct(this, 'WebUIHosting', {
      stackName: props.stackName,
    });
    applyConditionToSubtree(uiConstruct, frontendEnabled);

    this.webUIBucket = uiConstruct.bucket;
    // The distribution only exists when the frontend is deployed. Resolve its domain
    // through the condition so consumers never read an attribute of a resource that
    // was not created in an MCP-only deployment.
    this.distributionDomainName = cdk.Fn.conditionIf(
      frontendEnabled.logicalId,
      uiConstruct.distributionDomainName,
      '',
    ).toString();

    // Expose the domain as a conditioned nested-stack OUTPUT so the parent can read it via
    // Fn::GetAtt without importing the nested-only `frontendEnabled` condition. Referencing
    // `distributionDomainName` (an Fn::If on frontendEnabled) directly from the parent drags
    // that condition into the parent template, where it does not exist — CloudFormation
    // rejects it (E1028). The output keeps the condition inside this stack.
    const frontendDistributionDomainNameOutput = new cdk.CfnOutput(this, 'FrontendDistributionDomainName', {
      value: uiConstruct.distributionDomainName,
      condition: frontendEnabled,
    });
    this.distributionDomainNameOutputLogicalId = frontendDistributionDomainNameOutput.logicalId;

    const kmsKey = Key.fromKeyArn(this, 'ASR-EncryptionKey', props.kmsKeyARN);

    //---------------------------------------------------------------------
    // Admin Security Notifications Topic
    //
    // Infrastructure-defined SNS topic for mandatory admin-activity alerts on
    // security-critical configuration changes (notification channel and control
    // remediation changes). It is intentionally NOT exposed through any API route,
    // so Delegated Admins cannot alter its subscriptions. The entire WebUI nested
    // stack is conditional on `webUIEnabled` in the parent stack, so this topic is
    // only created when the Web UI is deployed.
    //
    const adminSecurityNotificationsTopic = new sns.Topic(this, 'AdminSecurityNotificationsTopic', {
      masterKey: kmsKey,
      enforceSSL: true,
    });

    // Subscribe the primary admin (deploy-time AdminUserEmail parameter). SNS email
    // subscriptions stay in PendingConfirmation until the recipient confirms via the
    // emailed link; no messages are delivered until then.
    adminSecurityNotificationsTopic.addSubscription(new snsSubscriptions.EmailSubscription(props.adminUserEmail));

    this.adminSecurityNotificationsTopic = adminSecurityNotificationsTopic;

    //---------------------------------------------------------------------
    // User Account Mapping Table - Stores user account access permissions
    //
    const userAccountMappingTable = new dynamodb.Table(this, 'UserAccountMappingTable', {
      partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.userAccountMappingTableARN = userAccountMappingTable.tableArn;
    this.userAccountMappingTableName = userAccountMappingTable.tableName;

    const cognitoConstruct = new CognitoConstruct(this, 'CognitoConstruct', {
      resourceNamePrefix: props.resourceNamePrefix,
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTMN,
      solutionsBucket: props.solutionsBucket,
      distributionDomainName: this.distributionDomainName,
      adminUserEmail: props.adminUserEmail,
      userAccountMappingTableName: userAccountMappingTable.tableName,
      userAccountMappingTable: userAccountMappingTable,
      multiFactorAuthentication: props.mfaConfiguration,
      frontendEnabled,
    });

    const apiConstruct = new ApiConstruct(this, 'ApiConstruct', {
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTMN,
      solutionsBucket: props.solutionsBucket,
      resourceNamePrefix: props.resourceNamePrefix,
      findingsTable: props.findingsTable,
      remediationHistoryTable: props.remediationHistoryTable,
      remediationConfigTable: props.remediationConfigTable,
      resourceFiltersTable: props.resourceFiltersTable,
      functionName: props.apiFunctionName,
      kmsKeyARN: props.kmsKeyARN,
      authorizer: cognitoConstruct.authorizer,
      deployApiGateway: frontendEnabled,
      userPoolId: cognitoConstruct.userPool.userPoolId,
      userAccountMappingTable: userAccountMappingTable,
      orchestratorArn: props.orchestratorArn,
      csvExportBucket: props.csvExportBucket,
      presignedUrlTTLDays: props.presignedUrlTTLDays,
      distributionDomainName: this.distributionDomainName,
      securityHubV2Enabled: props.securityHubV2Enabled,
      notificationConfigTable: props.notificationConfigTable,
      notificationBatchesTable: props.notificationBatchesTable,
      iacTemplatesBucket: props.iacTemplatesBucket,
      customRunbookTable: props.customRunbookTable,
      customRunbookBucket: props.customRunbookBucket,
      adminNotificationTopic: adminSecurityNotificationsTopic,
      enableRollback: props.enableRollback,
      findingsTtlDays: props.findingsTtlDays,
      mcpEnabled: props.mcpEnabled,
    });

    this.api = apiConstruct.api;

    // Expose the API endpoint as a conditioned nested-stack OUTPUT, for the same reason
    // as FrontendDistributionDomainName above. The API Gateway is frontend-gated
    // (deployApiGateway: frontendEnabled), so the parent must read its URL via Fn::GetAtt
    // on a conditioned output. Referencing apiConstruct.api.url from the parent directly
    // makes CDK synthesize an UNconditioned nested output over the API resource, which is
    // absent in an MCP-only (frontend-off) deployment — CloudFormation then fails the
    // nested stack with "Unresolved resource dependencies [...Api] in the Outputs block".
    const apiEndpointOutput = new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: apiConstruct.api.url,
      condition: frontendEnabled,
    });
    this.apiEndpointOutputLogicalId = apiEndpointOutput.logicalId;

    // The authorizer is an API Gateway resource that references the REST API, so it has to
    // disappear with it. It lives in the Cognito construct (the pool is its input), which
    // is why it is gated from out here rather than inside ApiConstruct.
    applyConditionToSubtree(cognitoConstruct.authorizer, frontendEnabled);

    this.userPoolId = cognitoConstruct.userPool.userPoolId;
    this.userPoolClientId = cognitoConstruct.userPoolClient.userPoolClientId;
    this.userPoolDomain = cognitoConstruct.userPoolDomain.domainName;

    // Copies the built UI assets into the CloudFront bucket, so it is meaningless
    // without the frontend and is gated with it.
    const webUIDeployment = new WebUIDeploymentConstruct(this, 'WebUIDeployment', {
      apiEndpoint: apiConstruct.api.url,
      awsRegion: config.development.region,
      userPoolId: cognitoConstruct.userPool.userPoolId,
      userPoolClientId: cognitoConstruct.userPoolClient.userPoolClientId,
      oauthDomain: cognitoConstruct.oauthDomain,
      distributionDomainName: uiConstruct.distributionDomainName,
      distributionId: uiConstruct.distributionId,
      solutionTMN: props.solutionTMN,
      sourceCodeBucket: props.solutionsBucket,
      destinationCodeBucket: uiConstruct.bucket,
      uiBucket: uiConstruct.bucket,
      solutionVersion: props.solutionVersion,
      stackId: cdk.Stack.of(this).stackId,
      ticketingGenFunction: props.ticketingGenFunction,
    });
    applyConditionToSubtree(webUIDeployment, frontendEnabled);
  }
}

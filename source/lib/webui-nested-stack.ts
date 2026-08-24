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
}

export class WebUINestedStack extends cdk.NestedStack {
  public readonly api: apigateway.RestApi;
  public readonly webUIBucket: s3.Bucket;
  public readonly distributionDomainName: string;
  public readonly userPoolId: string;
  public readonly userPoolClientId: string;
  public readonly userPoolDomain: string;
  public readonly userAccountMappingTableARN: string;
  public readonly adminSecurityNotificationsTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: WebUINestedStackProps) {
    super(scope, id, props);

    const config = getConfig();

    this.templateOptions.description = `(${props.solutionId}W) - Automated Security Response on AWS - WebUI nested stack for hosting the web user interface and API components. ${props.solutionVersion}`;

    const uiConstruct = new WebUIHostingConstruct(this, 'WebUIHosting', {
      stackName: props.stackName,
    });

    this.webUIBucket = uiConstruct.bucket;
    this.distributionDomainName = uiConstruct.distributionDomainName;

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

    const cognitoConstruct = new CognitoConstruct(this, 'CognitoConstruct', {
      resourceNamePrefix: props.resourceNamePrefix,
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTMN,
      solutionsBucket: props.solutionsBucket,
      distributionDomainName: uiConstruct.distributionDomainName,
      adminUserEmail: props.adminUserEmail,
      userAccountMappingTableName: userAccountMappingTable.tableName,
      userAccountMappingTable: userAccountMappingTable,
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
      adminNotificationTopic: adminSecurityNotificationsTopic,
    });

    this.api = apiConstruct.api;

    this.userPoolId = cognitoConstruct.userPool.userPoolId;
    this.userPoolClientId = cognitoConstruct.userPoolClient.userPoolClientId;
    this.userPoolDomain = cognitoConstruct.userPoolDomain.domainName;

    new WebUIDeploymentConstruct(this, 'WebUIDeployment', {
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
  }
}

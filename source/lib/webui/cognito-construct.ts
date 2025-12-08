// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import * as fs from 'node:fs';
import path from 'node:path';
import { CfnUserPoolUICustomizationAttachment } from 'aws-cdk-lib/aws-cognito';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';

export interface CognitoConstructProps {
  resourceNamePrefix: string;
  solutionId: string;
  solutionVersion: string;
  solutionTMN: string;
  solutionsBucket: s3.IBucket;
  multiFactorAuthentication?: string;
  distributionDomainName: string;
  adminUserEmail: string;
  userAccountMappingTableName: string;
}

export class CognitoConstruct extends Construct {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly userPoolDomain: cognito.UserPoolDomain;
  public readonly authorizer: apigateway.CognitoUserPoolsAuthorizer;
  public readonly adminGroup: cognito.CfnUserPoolGroup;
  public readonly delegatedAdminGroup: cognito.CfnUserPoolGroup;
  public readonly accountOperatorGroup: cognito.CfnUserPoolGroup;
  public readonly oauthDomain: string;

  constructor(scope: Construct, id: string, props: CognitoConstructProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);

    const preSignupTrigger = new lambda.Function(this, 'PreSignupTrigger', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'api/handlers/preSignUp.preSignUpHandler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      description: 'ASR Cognito pre-signup trigger function',
      environment: {
        POWERTOOLS_LOG_LEVEL: 'INFO',
        USER_ACCOUNT_MAPPING_TABLE_NAME: props.userAccountMappingTableName,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(60),
      tracing: lambda.Tracing.ACTIVE,
    });

    // Add IAM permissions for the pre-signup trigger
    preSignupTrigger.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cognito-idp:AdminListGroupsForUser',
          'cognito-idp:AdminLinkProviderForUser',
          'cognito-idp:AdminGetUser',
          'cognito-idp:AdminDeleteUser',
          'cognito-idp:DescribeIdentityProvider',
        ],
        resources: [`arn:${stack.partition}:cognito-idp:${stack.region}:${stack.account}:userpool/*`],
      }),
    );

    addCfnGuardSuppression(preSignupTrigger, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(preSignupTrigger, 'LAMBDA_CONCURRENCY_CHECK');

    const emailSubject = 'Welcome to Automated Security Response on AWS';

    const createInvitationEmailBody = (): string => {
      return `
        <p>Hello,</p>
        <p>You have been invited to access the Automated Security Response on AWS solution.</p>
        <p>Your username is: <strong>{username}</strong></p>
        <p>Your temporary password is: <strong>{####}</strong></p>
        <p>Web UI URL:</p>
        <p><a href="https://${props.distributionDomainName}">https://${props.distributionDomainName}</a></p>
        <p>Please use the above URL to sign in and change your password.</p>
      `;
    };

    this.userPool = new cognito.UserPool(this, 'ASRUserPool', {
      userPoolName: `${props.resourceNamePrefix}-ASR-UserPool`,
      signInAliases: {
        email: true,
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: cdk.Duration.days(7),
      },
      selfSignUpEnabled: false,
      userInvitation: {
        emailSubject: emailSubject,
        emailBody: createInvitationEmailBody(),
      },
      mfa: (props.multiFactorAuthentication as cognito.Mfa) || cognito.Mfa.OPTIONAL,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      autoVerify: {
        email: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      // Add custom attributes required by Lambda services
      customAttributes: {
        invitedBy: new cognito.StringAttribute({ mutable: true }),
      },
      lambdaTriggers: {
        preSignUp: preSignupTrigger,
      },
    });

    const resourceServer = new cognito.UserPoolResourceServer(this, 'ASRResourceServer', {
      userPool: this.userPool,
      identifier: 'asr-api',
      scopes: [
        {
          scopeName: 'api',
          scopeDescription: 'Access to ASR API endpoints',
        },
      ],
    });

    const isDevelopmentEnv = process.env.BUILD_ENV === 'development';
    const callbackUrls = [`https://${props.distributionDomainName}/callback`];
    const logoutUrls = [`https://${props.distributionDomainName}`];

    if (isDevelopmentEnv) {
      callbackUrls.push('http://localhost:3000/callback');
      logoutUrls.push('http://localhost:3000');
    }

    this.userPoolClient = new cognito.UserPoolClient(this, 'ASRUserPoolClient', {
      userPool: this.userPool,
      userPoolClientName: `${props.resourceNamePrefix}-ASR-WebUI-UserPoolClient`,
      generateSecret: false,
      authFlows: {
        userSrp: true,
      },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
        },
        scopes: [
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.COGNITO_ADMIN,
          cognito.OAuthScope.custom('asr-api/api'),
        ],
        callbackUrls,
        logoutUrls,
      },
    });

    this.userPoolDomain = new cognito.UserPoolDomain(this, 'ASRUserPoolDomain', {
      userPool: this.userPool,
      cognitoDomain: {
        domainPrefix: `${props.resourceNamePrefix.toLowerCase()}-asr-${cdk.Stack.of(this).account}`,
      },
      managedLoginVersion: cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
    });

    this.oauthDomain = `${props.resourceNamePrefix.toLowerCase()}-asr-${cdk.Stack.of(this).account}.auth.${cdk.Stack.of(this).region}.amazoncognito.com`;

    this.userPoolClient.node.addDependency(resourceServer);

    this.authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'ASRCognitoAuthorizer', {
      cognitoUserPools: [this.userPool],
      authorizerName: 'ASRCognitoAuthorizer',
      identitySource: 'method.request.header.Authorization',
    });

    this.adminGroup = new cognito.CfnUserPoolGroup(this, 'AdminGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: 'AdminGroup',
      description:
        'Full administrative access to ASR Web UI. Can view and remediate findings across all accounts, access all historical data, and manage all users.',
      precedence: 1,
    });

    this.delegatedAdminGroup = new cognito.CfnUserPoolGroup(this, 'DelegatedAdminGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: 'DelegatedAdminGroup',
      description:
        'Full access to view and remediate findings across all accounts. Can invite Account Operators and manage their access.',
      precedence: 2,
    });

    this.accountOperatorGroup = new cognito.CfnUserPoolGroup(this, 'AccountOperatorGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: 'AccountOperatorGroup',
      description:
        'Limited access to findings and remediation for specific accounts only. Account access is defined during invitation.',
      precedence: 3,
    });

    // Create Admin User with required custom attributes
    const adminUser = new cognito.CfnUserPoolUser(this, 'AdminUser', {
      userPoolId: this.userPool.userPoolId,
      username: props.adminUserEmail,
      userAttributes: [
        {
          name: 'email',
          value: props.adminUserEmail,
        },
        {
          name: 'email_verified',
          value: 'true',
        },
        {
          name: 'custom:invitedBy',
          value: 'system',
        },
      ],
    });

    new cognito.CfnUserPoolUserToGroupAttachment(this, 'AdminUserToAdminGroup', {
      userPoolId: this.userPool.userPoolId,
      username: adminUser.ref,
      groupName: this.adminGroup.ref,
    });

    adminUser.addDependency(this.userPool.node.defaultChild as cognito.CfnUserPool);
    adminUser.addDependency(this.adminGroup);

    const userPoolResource = this.userPool.node.findChild('Resource') as cognito.CfnUserPool;

    // Load managed login branding settings JSON
    const brandingJsonPath = path.resolve(__dirname, '../../webui/public/cognito-managed-login-branding.json');
    const brandingJsonContent = fs.readFileSync(brandingJsonPath, 'utf8');
    const brandingSettings = JSON.parse(brandingJsonContent);

    const transformedAssets = brandingSettings.ManagedLoginBranding.Assets.map((asset: any) => ({
      category: asset.Category,
      colorMode: asset.ColorMode,
      extension: asset.Extension,
      bytes: asset.Bytes,
    }));

    const managedLoginBranding = new cognito.CfnManagedLoginBranding(this, 'ManagedLoginBranding', {
      userPoolId: this.userPool.userPoolId,
      clientId: this.userPoolClient.userPoolClientId,
      settings: brandingSettings.ManagedLoginBranding.Settings,
      assets: transformedAssets,
      useCognitoProvidedValues: false,
    });

    // avoid race condition where customization is attempting to be applied before domain is active
    managedLoginBranding.addDependency(this.userPoolDomain.node.defaultChild as cognito.CfnUserPoolDomain);

    userPoolResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W78',
            reason: 'MFA is configured as optional and can be enforced based on requirements.',
          },
        ],
      },
    };

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: this.userPool.userPoolId,
      description: 'Cognito User Pool ID',
      exportName: `${cdk.Stack.of(this).stackName}-UserPoolId`,
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: this.userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
      exportName: `${cdk.Stack.of(this).stackName}-UserPoolClientId`,
    });
  }
}

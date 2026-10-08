// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import * as fs from 'node:fs';
import path from 'node:path';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from '../cdk-helper/log-group';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';
import { getConfig } from '../config/cdk-config';

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
  userAccountMappingTable: dynamodb.ITable;
  /**
   * Gates the frontend-only Web UI SPA app client (and its managed-login branding and
   * client-id output). The client's OAuth callback/logout URLs are derived from the
   * CloudFront distribution domain, which only exists when the frontend is deployed; in
   * an MCP-only deployment that domain resolves to '', producing invalid `https:///callback`
   * URLs that Cognito rejects. The user pool, its hosted-UI domain, and the resource server
   * stay unconditional — the AgentCore Gateway and its own app client depend on them.
   */
  frontendEnabled: cdk.CfnCondition;
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
      runtime: lambda.Runtime.NODEJS_24_X,
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
      logGroup: createLogGroup(this, 'PreSignupTriggerLogGroup'),
    });

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

    preSignupTrigger.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:Query'],
        resources: [
          `arn:${stack.partition}:dynamodb:${stack.region}:${stack.account}:table/${props.userAccountMappingTableName}`,
        ],
      }),
    );

    preSignupTrigger.node.addDependency(props.userAccountMappingTable);

    addCfnGuardSuppression(preSignupTrigger, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(preSignupTrigger, 'LAMBDA_CONCURRENCY_CHECK');

    const emailSubject = 'Welcome to Automated Security Response on AWS';
    const multiFactorAuthentication = props.multiFactorAuthentication || cognito.Mfa.OPTIONAL;

    // The invitation email is sent whenever the user pool exists — including an MCP-only
    // deployment, where the CloudFront frontend (and therefore distributionDomainName) is
    // absent and resolves to ''. Choose the whole body at deploy time:
    //   - frontend on  → link to the Web UI (CloudFront).
    //   - frontend off → no Web UI link (there is none, and a bare Cognito hosted-UI
    //     /login is not a usable login URL without client_id/response_type/scope/
    //     redirect_uri); instead tell the user to sign in from their MCP client, which
    //     drives the OAuth login flow itself.
    const webUiEmailBody = `
        <p>Hello,</p>
        <p>You have been invited to access the Automated Security Response on AWS solution.</p>
        <p>Your username is: <strong>{username}</strong></p>
        <p>Your temporary password is: <strong>{####}</strong></p>
        <p>Web UI URL:</p>
        <p><a href="https://${props.distributionDomainName}">https://${props.distributionDomainName}</a></p>
        <p>Please use the above URL to sign in and change your password.</p>
      `;
    const mcpOnlyEmailBody = `
        <p>Hello,</p>
        <p>You have been invited to access the Automated Security Response on AWS solution.</p>
        <p>Your username is: <strong>{username}</strong></p>
        <p>Your temporary password is: <strong>{####}</strong></p>
        <p>This deployment has no Web UI. Sign in from your MCP client (for example Kiro, Claude Code, or Codex): start the ASR gateway login when prompted and enter the username and temporary password above. You will be asked to set a new password on first sign-in.</p>
      `;
    const invitationEmailBody = cdk.Fn.conditionIf(
      props.frontendEnabled.logicalId,
      webUiEmailBody,
      mcpOnlyEmailBody,
    ).toString();

    const createInvitationEmailBody = (): string => invitationEmailBody;

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
      mfa: multiFactorAuthentication as cognito.Mfa,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      autoVerify: {
        email: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      customAttributes: {
        invitedBy: new cognito.StringAttribute({ mutable: true }),
      },
      lambdaTriggers: {
        preSignUp: preSignupTrigger,
      },
    });

    const isMultiFactorAuthenticationOff = new cdk.CfnCondition(this, 'IsMultiFactorAuthenticationOff', {
      expression: cdk.Fn.conditionEquals(multiFactorAuthentication, cognito.Mfa.OFF),
    });
    const userPoolCloudFormationResource = this.userPool.node.defaultChild as cognito.CfnUserPool;
    userPoolCloudFormationResource.addPropertyOverride(
      'EnabledMfas',
      cdk.Fn.conditionIf(isMultiFactorAuthenticationOff.logicalId, cdk.Aws.NO_VALUE, ['SOFTWARE_TOKEN_MFA']),
    );

    // The MFAConfiguration parameter accepts OFF | OPTIONAL | REQUIRED, but the CloudFormation
    // AWS::Cognito::UserPool.MfaConfiguration property only accepts OFF | ON | OPTIONAL. Because
    // multiFactorAuthentication is an unresolved CFN token, CDK cannot map REQUIRED -> ON at
    // synth (that mapping only happens for the resolved cognito.Mfa.REQUIRED enum), so the raw
    // 'REQUIRED' string would be emitted and rejected at deploy. Override MfaConfiguration to
    // translate REQUIRED -> ON at deploy time; OFF/OPTIONAL pass through unchanged. Compare
    // against the literal 'REQUIRED' (the parameter value), not cognito.Mfa.REQUIRED (== 'ON').
    const isMultiFactorAuthenticationRequired = new cdk.CfnCondition(this, 'IsMultiFactorAuthenticationRequired', {
      expression: cdk.Fn.conditionEquals(multiFactorAuthentication, 'REQUIRED'),
    });
    userPoolCloudFormationResource.addPropertyOverride(
      'MfaConfiguration',
      cdk.Fn.conditionIf(isMultiFactorAuthenticationRequired.logicalId, 'ON', multiFactorAuthentication),
    );

    const resourceServer = new cognito.UserPoolResourceServer(this, 'ASRResourceServer', {
      userPool: this.userPool,
      identifier: 'asr-api',
      scopes: [
        {
          scopeName: 'api',
          scopeDescription: 'Access to ASR API endpoints',
        },
        {
          // Granting a machine (client_credentials) token this scope yields Full
          // Access in the API Lambda. No app client is provisioned here: the
          // customer creates a confidential client granted this scope post-deploy
          // (see docs/m2m-authentication.md), so the feature is inert by default.
          scopeName: 'full-access',
          scopeDescription: 'Full administrative access to the ASR API for machine-to-machine clients',
        },
        {
          // Scope required on tokens that reach the API via the (optional,
          // parameter-gated) AgentCore Gateway. Its inbound JWT authorizer
          // validates this scope; the ACG app client is granted it. Kept
          // distinct from full-access so gateway traffic is separately grantable.
          scopeName: 'gateway',
          scopeDescription: 'Access to the ASR API through the AgentCore Gateway',
        },
      ],
    });

    const config = getConfig();
    const isDevelopmentEnv = config.development.buildEnv === 'development';
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
    // Frontend-only: the callback/logout URLs above are meaningless (and invalid) without
    // the CloudFront distribution, so the SPA client is created only when the frontend is.
    (this.userPoolClient.node.defaultChild as cognito.CfnUserPoolClient).cfnOptions.condition = props.frontendEnabled;

    this.userPoolDomain = new cognito.UserPoolDomain(this, 'ASRUserPoolDomain', {
      userPool: this.userPool,
      cognitoDomain: {
        domainPrefix: `${props.resourceNamePrefix.toLowerCase()}-asr-${cdk.Stack.of(this).account}`,
      },
      managedLoginVersion: cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
    });

    this.oauthDomain = `${props.resourceNamePrefix.toLowerCase()}-asr-${cdk.Stack.of(this).account}.auth.${cdk.Stack.of(this).region}.amazoncognito.com`;

    this.userPoolClient.node.addDependency(resourceServer);

    // Machine-to-machine (M2M) Full Access is enabled by the customer creating a
    // confidential `client_credentials` app client granted the `asr-api/full-access`
    // scope post-deploy (see docs/m2m-authentication.md). No client is provisioned
    // here: Cognito requires a secret on a client_credentials client at creation and
    // has no API to add one later, so a deploy-time client cannot be shipped inert.
    // The API Lambda authorizes such tokens by inspecting the `asr-api/full-access`
    // scope claim, so no client id needs to be known at deploy time.

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

    adminUser.addResourceDependency(this.userPool.node.defaultChild as cognito.CfnUserPool);
    adminUser.addResourceDependency(this.adminGroup);
    adminUser.addResourceDependency(this.userPoolDomain.node.defaultChild as cognito.CfnUserPoolDomain);

    const userPoolResource = this.userPool.node.findChild('Resource') as cognito.CfnUserPool;

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
    // Branding is bound to the frontend SPA client, so it must disappear with it.
    managedLoginBranding.cfnOptions.condition = props.frontendEnabled;

    // avoid race condition where customization is attempting to be applied before domain is active
    managedLoginBranding.addResourceDependency(this.userPoolDomain.node.defaultChild as cognito.CfnUserPoolDomain);

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
      // References the frontend-only SPA client, so it is gated with it — otherwise the
      // output resolves an attribute of a resource that does not exist in MCP-only mode.
      condition: props.frontendEnabled,
    });
  }
}

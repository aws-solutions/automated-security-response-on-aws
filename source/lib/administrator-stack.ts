// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { App, CfnOutput, CfnRule, CustomResource, Duration, Fn } from 'aws-cdk-lib';
import {
  AccountRootPrincipal,
  CfnPolicy,
  CfnRole,
  Policy,
  PolicyDocument,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Tracing } from 'aws-cdk-lib/aws-lambda';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { CfnParameter, StringParameter } from 'aws-cdk-lib/aws-ssm';
import { CfnStateMachine, StateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { scPlaybookProps, standardPlaybookProps } from '../playbooks/playbook-index';
import { ActionLog } from './action-log';
import { AdminPlaybook } from './admin-playbook';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import MetricResources from './cdk-helper/metric-resources';
import { CloudWatchMetrics } from './cloudwatch_metrics';
import { OrchestratorConstruct } from './common-orchestrator-construct';
import { ASRParameters } from './constants/parameters';
import { PreProcessorConstruct } from './pre-processor-construct';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { OneTrigger, Trigger } from './ssmplaybook';
import { SynchronizationFindingsConstruct } from './synchronization-findings-construct';
import { WebUINestedStack } from './webui-nested-stack';
import { AttributeType, BillingMode, Table, TableEncryption } from 'aws-cdk-lib/aws-dynamodb';

export interface ASRStackProps extends cdk.StackProps {
  solutionId: string;
  solutionVersion: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionName: string;
  runtimePython: lambda.Runtime;
  orchestratorLogGroup: string;
  SNSTopicName: string;
  cloudTrailLogGroupName: string;
}

export class AdministratorStack extends cdk.Stack {
  constructor(scope: App, id: string, props: ASRStackProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);
    const RESOURCE_NAME_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    //=============================================================================================
    // Parameters
    //=============================================================================================
    //-------------------------------------------------------------------------
    // Solutions Bucket - Source Code
    //
    const sourceCodeBucket = s3.Bucket.fromBucketAttributes(this, 'SourceCodeBucket', {
      bucketName: props.solutionDistBucket + '-' + this.region,
    });

    const solutionsReferenceBucket = props.solutionDistBucket + '-reference';
    const solutionsReferenceBucketPartition = stack.partition;
    const customReferenceBucketRegion = process.env.CUSTOM_REFERENCE_BUCKET_REGION ?? '';
    const findingsTTL = process.env.FINDINGS_TTL_DAYS || '8';
    const historyTTL = process.env.HISTORY_TTL_DAYS || '365';
    const exportFilesTTL = process.env.EXPORTFILES_TTL_DAYS ? Number(process.env.EXPORTFILES_TTL_DAYS) : 30;
    const presignedUrlTTL = process.env.PRESIGNED_URL_TTL_DAYS ? Number(process.env.PRESIGNED_URL_TTL_DAYS) : 1; // maximum allowed value is 1 day
    const orchestratorTimeoutHours = process.env.ORCHESTRATOR_TIMEOUT_HOURS
      ? Number(process.env.ORCHESTRATOR_TIMEOUT_HOURS)
      : 23;
    const enableAdaptiveConcurrency = process.env.ENABLE_ADAPTIVE_CONCURRENCY || true;

    // Pre-processor function name
    const preProcessorFunctionName = `${props.solutionId}-ASR-PreProcessor`;
    const apiFunctionName = `${props.solutionId}-ASR-APIs`;

    //=========================================================================
    // MAPPINGS
    //=========================================================================
    new cdk.CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionTMN + '/' + props.solutionVersion,
        },
      },
    });

    //-------------------------------------------------------------------------
    // KMS Key for solution encryption
    //

    // Key Policy
    const kmsKeyPolicy: PolicyDocument = new PolicyDocument();

    const kmsActions = ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'];

    const kmsServicePolicy = new PolicyStatement({
      principals: [new ServicePrincipal('sns.amazonaws.com'), new ServicePrincipal(`logs.${this.urlSuffix}`)],
      actions: kmsActions,
      resources: ['*'],
      conditions: {
        ArnEquals: {
          'kms:EncryptionContext:aws:logs:arn': this.formatArn({
            service: 'logs',
            resource: 'log-group:SO0111-ASR-*',
          }),
        },
      },
    });
    kmsKeyPolicy.addStatements(kmsServicePolicy);

    // key encrypts DynamoDB tables and Pre-processor queue
    const kmsGeneralServicePolicy = new PolicyStatement({
      principals: [
        new ServicePrincipal('dynamodb.amazonaws.com'),
        new ServicePrincipal('events.amazonaws.com'), // remediation Trigger requires access to encrypted pre-processor queue
        new ServicePrincipal('sqs.amazonaws.com'),
      ],
      actions: kmsActions,
      resources: ['*'],
    });
    kmsKeyPolicy.addStatements(kmsGeneralServicePolicy);

    // Pre-processor lambda requires access to encrypted Findings table
    const kmsPreProcessorPolicy = new PolicyStatement({
      principals: [new ServicePrincipal('lambda.amazonaws.com')],
      actions: kmsActions,
      resources: [`arn:${this.partition}:lambda:${this.region}:${this.account}:function:${preProcessorFunctionName}`],
    });
    kmsKeyPolicy.addStatements(kmsPreProcessorPolicy);

    const kmsRootPolicy = new PolicyStatement({
      principals: [new AccountRootPrincipal()],
      actions: ['kms:*'],
      resources: ['*'],
    });
    kmsKeyPolicy.addStatements(kmsRootPolicy);

    const kmsKey = new kms.Key(this, 'SHARR-key', {
      enableKeyRotation: true,
      alias: `${RESOURCE_NAME_PREFIX}-SHARR-Key`,
      policy: kmsKeyPolicy,
    });

    const kmsKeyParm = new StringParameter(this, 'SHARR_Key', {
      description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
      parameterName: `/Solutions/${RESOURCE_NAME_PREFIX}/CMK_ARN`,
      stringValue: kmsKey.keyArn,
    });

    //-------------------------------------------------------------------------
    // SNS Topic for notification fanout on Playbook completion
    //
    const primarySolutionTopic = new sns.Topic(this, 'SHARR-Topic', {
      displayName: `Automated Security Response on AWS (${RESOURCE_NAME_PREFIX}) Status Topic`,
      topicName: props.SNSTopicName,
      masterKey: kmsKey,
    });

    new StringParameter(this, 'SHARR_SNS_Topic', {
      description:
        'SNS Topic ARN where ASR will send status messages. This topic can be useful for driving additional actions, such as email notifications, trouble ticket updates.',
      parameterName: '/Solutions/' + RESOURCE_NAME_PREFIX + '/SNS_Topic_ARN',
      stringValue: primarySolutionTopic.topicArn,
    });

    new StringParameter(this, 'SHARR_version', {
      description: 'Solution version for metrics.',
      parameterName: '/Solutions/' + RESOURCE_NAME_PREFIX + '/version',
      stringValue: props.solutionVersion,
    });

    new StringParameter(this, 'ASR_AccountFilters', {
      description:
        'List of AWS Account IDs to filter remediations. Default value: none. Note: Filter only apply to automated runs, not manual executions.',
      parameterName: ASRParameters.ACCOUNT_FILTERS,
      stringValue: ASRParameters.DEFAULT_FILTER_VALUE,
      allowedPattern: ASRParameters.ACCOUNT_FILTER_PATTERN.source,
    });

    new StringParameter(this, 'ASR_AccountFilterMode', {
      description: "Set to 'Include', 'Exclude', or 'Disabled' to control AccountFilter.",
      parameterName: ASRParameters.ACCOUNT_FILTER_MODE,
      stringValue: ASRParameters.DEFAULT_FILTER_MODE,
      allowedPattern: ASRParameters.DEFAULT_FILTER_MODE_PATTERN.source,
    });

    new StringParameter(this, 'ASR_OUFilters', {
      description:
        'List of organizational units to filter remediations. Default value: none. Note: Filter only apply to automated runs, not manual executions.',
      parameterName: ASRParameters.OU_FILTERS,
      stringValue: ASRParameters.DEFAULT_FILTER_VALUE,
      allowedPattern: ASRParameters.OU_FILTER_PATTERN.source,
    });

    new StringParameter(this, 'ASR_OUFilterMode', {
      description: "Set to 'Include', 'Exclude', or 'Disabled' to control OUFilters",
      parameterName: ASRParameters.OU_FILTER_MODE,
      stringValue: ASRParameters.DEFAULT_FILTER_MODE,
      allowedPattern: ASRParameters.DEFAULT_FILTER_MODE_PATTERN.source,
    });

    new StringParameter(this, 'ASR_TagFilters', {
      description:
        'List of tag keys to filter remediations. Default value: none. Note: Filter only apply to automated runs, not manual executions.',
      parameterName: ASRParameters.TAG_FILTERS,
      stringValue: ASRParameters.DEFAULT_FILTER_VALUE,
      allowedPattern: ASRParameters.TAG_FILTER_PATTERN.source,
    });

    new StringParameter(this, 'ASR_TagFilterMode', {
      description: "Set to 'Include', 'Exclude', or 'Disabled' to control TagFilters",
      parameterName: ASRParameters.TAG_FILTER_MODE,
      stringValue: ASRParameters.DEFAULT_FILTER_MODE,
      allowedPattern: ASRParameters.DEFAULT_FILTER_MODE_PATTERN.source,
    });

    //---------------------------------------------------------------------
    // ASR Findings Table - Stores findings that ASR supports for remediation
    //
    const asrFindingsTable = new Table(this, 'ASRFindingsTable', {
      partitionKey: { name: 'findingType', type: AttributeType.STRING },
      sortKey: { name: 'findingId', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      timeToLiveAttribute: 'expireAt',
    });

    // Local Secondary Index
    asrFindingsTable.addLocalSecondaryIndex({
      indexName: 'securityHubUpdatedAtTime-findingId-LSI',
      sortKey: { name: 'securityHubUpdatedAtTime#findingId', type: AttributeType.STRING },
    });

    // Global Secondary Index 1: accountId
    asrFindingsTable.addGlobalSecondaryIndex({
      indexName: 'accountId-securityHubUpdatedAtTime-GSI',
      partitionKey: { name: 'accountId', type: AttributeType.STRING },
      sortKey: { name: 'securityHubUpdatedAtTime#findingId', type: AttributeType.STRING },
    });

    // Global Secondary Index 2: resourceId
    asrFindingsTable.addGlobalSecondaryIndex({
      indexName: 'resourceId-securityHubUpdatedAtTime-GSI',
      partitionKey: { name: 'resourceId', type: AttributeType.STRING },
      sortKey: { name: 'securityHubUpdatedAtTime#findingId', type: AttributeType.STRING },
    });

    // Global Secondary Index 3: Severity
    asrFindingsTable.addGlobalSecondaryIndex({
      indexName: 'severity-securityHubUpdatedAtTime-GSI',
      partitionKey: { name: 'severity', type: AttributeType.STRING },
      sortKey: { name: 'securityHubUpdatedAtTime#findingId', type: AttributeType.STRING },
    });

    // Global Secondary Index 4: All findings sorted by securityHubUpdatedAtTime
    asrFindingsTable.addGlobalSecondaryIndex({
      indexName: 'allFindings-securityHubUpdatedAtTime-GSI',
      partitionKey: { name: 'FINDING_CONSTANT', type: AttributeType.STRING },
      sortKey: { name: 'securityHubUpdatedAtTime#findingId', type: AttributeType.STRING },
    });

    // Global Secondary Index 5: All findings sorted by severity (normalized) then time
    asrFindingsTable.addGlobalSecondaryIndex({
      indexName: 'allFindings-severityNormalized-GSI',
      partitionKey: { name: 'FINDING_CONSTANT', type: AttributeType.STRING },
      sortKey: { name: 'severityNormalized#securityHubUpdatedAtTime#findingId', type: AttributeType.STRING },
    });

    //---------------------------------------------------------------------
    // ASR Remediation History Table - Stores remediation execution history
    //
    const remediationHistoryTable = new Table(this, 'ASRRemediationHistoryTable', {
      partitionKey: { name: 'findingType', type: AttributeType.STRING },
      sortKey: { name: 'findingId#executionId', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: kmsKey,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      timeToLiveAttribute: 'expireAt',
    });

    // GSI1: AccountID (Partition key), lastUpdatedTime#FindingId (Sort Key)
    remediationHistoryTable.addGlobalSecondaryIndex({
      indexName: 'accountId-lastUpdatedTime-GSI',
      partitionKey: { name: 'accountId', type: AttributeType.STRING },
      sortKey: { name: 'lastUpdatedTime#findingId', type: AttributeType.STRING },
    });

    // GSI2: UserId (Partition key), lastUpdatedTime#FindingId (Sort Key)
    remediationHistoryTable.addGlobalSecondaryIndex({
      indexName: 'userId-lastUpdatedTime-GSI',
      partitionKey: { name: 'userId', type: AttributeType.STRING },
      sortKey: { name: 'lastUpdatedTime#findingId', type: AttributeType.STRING },
    });

    // GSI3: ResourceID (Partition key), lastUpdatedTime#FindingId (Sort Key)
    remediationHistoryTable.addGlobalSecondaryIndex({
      indexName: 'resourceId-lastUpdatedTime-GSI',
      partitionKey: { name: 'resourceId', type: AttributeType.STRING },
      sortKey: { name: 'lastUpdatedTime#findingId', type: AttributeType.STRING },
    });

    // GSI4: "remediation" (Partition key – constant), lastUpdatedTime#FindingId (Sort Key)
    remediationHistoryTable.addGlobalSecondaryIndex({
      indexName: 'allRemediations-lastUpdatedTime-GSI',
      partitionKey: { name: 'REMEDIATION_CONSTANT', type: AttributeType.STRING },
      sortKey: { name: 'lastUpdatedTime#findingId', type: AttributeType.STRING },
    });

    // GSI5: FindingId (Partition key), lastUpdatedTime#FindingId (Sort Key) - For efficient CSV export
    remediationHistoryTable.addGlobalSecondaryIndex({
      indexName: 'findingId-lastUpdatedTime-GSI',
      partitionKey: { name: 'findingId', type: AttributeType.STRING },
      sortKey: { name: 'lastUpdatedTime#findingId', type: AttributeType.STRING },
    });

    const asrLambdaLayer = new lambda.LayerVersion(this, 'ASRLambdaLayer', {
      compatibleRuntimes: [props.runtimePython],
      description: 'SO0111 ASR Common functions used by the solution',
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'layer.zip'),
    });

    /**
     * @description Policy for role used by common Orchestrator Lambdas
     * @type {Policy}
     */
    const orchestratorPolicy = new Policy(this, 'orchestratorPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Orchestrator',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter', 'ssm:DeleteParameter'],
          resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['sts:AssumeRole'],
          resources: [
            `arn:${this.partition}:iam::*:role/${RESOURCE_NAME_PREFIX}-ASR-Orchestrator-Member`,
            //'arn:' + this.partition + ':iam::*:role/' + RESOURCE_NAME_PREFIX +
            //'-Remediate-*',
          ],
        }),
        // Supports https://gitlab.aws.dev/dangibbo/sharr-remediation-framework
        new PolicyStatement({
          actions: ['organizations:ListTagsForResource'],
          resources: ['*'],
        }),
      ],
    });

    {
      const childToMod = orchestratorPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for read-only policies used by orchestrator Lambda functions.',
            },
          ],
        },
      };
    }

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {Role}
     */

    const orchestratorRole: Role = new Role(this, 'orchestratorRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to allow cross account read-only ASR orchestrator functions',
      roleName: `${RESOURCE_NAME_PREFIX}-ASR-Orchestrator-Admin`,
    });

    orchestratorRole.attachInlinePolicy(orchestratorPolicy);

    {
      const childToMod = orchestratorRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason:
                'Static names chosen intentionally to provide easy integration with playbook orchestrator step functions.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(orchestratorRole, 'IAM_NO_INLINE_POLICY_CHECK');

    const checkSSMDocumentState = new lambda.Function(this, 'checkSSMDocumentState', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-checkSSMDocumentState',
      handler: 'check_ssm_doc_state.lambda_handler',
      runtime: props.runtimePython,
      description: 'Checks the status of an SSM Automation Document in the target account',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'check_ssm_doc_state.zip'),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'check_ssm_doc_state',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = checkSSMDocumentState.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description getApprovalRequirement - determine whether manual approval is required
     * @type {lambda.Function}
     */
    const getApprovalRequirement = new lambda.Function(this, 'getApprovalRequirement', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-getApprovalRequirement',
      handler: 'get_approval_requirement.lambda_handler',
      runtime: props.runtimePython,
      description: 'Determines if a manual approval is required for remediation',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'get_approval_requirement.zip'),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        WORKFLOW_RUNBOOK: '',
        SOLUTION_TMN: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'get_approval_requirement',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = getApprovalRequirement.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description execAutomation - initiate an SSM automation document in a target account
     * @type {lambda.Function}
     */
    const execAutomation = new lambda.Function(this, 'execAutomation', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-execAutomation',
      handler: 'exec_ssm_doc.lambda_handler',
      runtime: props.runtimePython,
      description: 'Executes an SSM Automation Document in a target account',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'exec_ssm_doc.zip'),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'exec_ssm_doc',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = execAutomation.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description monitorSSMExecState - get the status of an ssm execution
     * @type {lambda.Function}
     */
    const monitorSSMExecState = new lambda.Function(this, 'monitorSSMExecState', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-monitorSSMExecState',
      handler: 'check_ssm_execution.lambda_handler',
      runtime: props.runtimePython,
      description: 'Checks the status of an SSM automation document execution',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'check_ssm_execution.zip'),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'check_ssm_execution',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = monitorSSMExecState.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description Policy for role used by common Orchestrator notification lambda
     * @type {Policy}
     */
    const notifyPolicy = new Policy(this, 'notifyPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Orchestrator_Notifier',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['securityhub:BatchUpdateFindings'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter'],
          resources: [`arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [kmsKey.keyArn],
        }),
        new PolicyStatement({
          actions: ['sns:Publish'],
          resources: [`arn:${this.partition}:sns:${this.region}:${this.account}:${RESOURCE_NAME_PREFIX}-ASR_Topic`],
        }),
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['organizations:DescribeAccount'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['dynamodb:UpdateItem', 'dynamodb:PutItem', 'dynamodb:GetItem'],
          resources: [asrFindingsTable.tableArn, remediationHistoryTable.tableArn],
        }),
      ],
    });

    {
      const childToMod = notifyPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason:
                'Resource * is required for CloudWatch Logs and Security Hub policies used by core solution Lambda function for notifications.',
            },
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
          ],
        },
      };
    }

    notifyPolicy.attachToRole(orchestratorRole); // Any Orchestrator Lambda can send to sns

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {Role}
     */

    const notifyRole: Role = new Role(this, 'notifyRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to perform notification and logging from orchestrator step function',
    });

    notifyRole.attachInlinePolicy(notifyPolicy);

    {
      const childToMod = notifyRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason:
                'Static names chosen intentionally to provide easy integration with playbook orchestrator step functions.',
            },
          ],
        },
      };
    }

    // Defined outside cloudwatch_metrics.ts to avoid dependency loop between cloudWatchMetrics and orchStateMachine
    const enableEnhancedCloudWatchMetrics = new cdk.CfnParameter(this, 'EnableEnhancedCloudWatchMetrics', {
      type: 'String',
      description: `Enable collection of metrics per Control ID in addition to standard metrics. You must also select 'yes' for UseCloudWatchMetrics to enable enhanced metric collection. The added cost of these additional custom metrics could be up to $67.20/month.`,
      default: 'no',
      allowedValues: ['yes', 'no'],
    });

    const enhancedMetricsEnabled = new cdk.CfnCondition(this, 'enhancedMetricsEnabled', {
      expression: Fn.conditionEquals(enableEnhancedCloudWatchMetrics.valueAsString, 'yes'),
    });

    //-------------------------------------------------------------------------
    // WebUI Deployment Parameter
    //
    const shouldDeployWebUI = new cdk.CfnParameter(this, 'ShouldDeployWebUI', {
      type: 'String',
      description:
        'Deploy the Web UI components including API Gateway, Lambda functions, and CloudFront distribution. Select "yes" to enable the web-based dashboard for viewing findings and remediation status.',
      default: 'yes',
      allowedValues: ['yes', 'no'],
    });

    const webUIEnabled = new cdk.CfnCondition(this, 'webUIEnabled', {
      expression: Fn.conditionEquals(shouldDeployWebUI.valueAsString, 'yes'),
    });

    const adminUserEmail = new cdk.CfnParameter(this, 'AdminUserEmail', {
      type: 'String',
      description:
        'Email address for the initial admin user. This user will have full administrative access to the ASR Web UI. Required when Web UI is enabled.',
      default: '',
    });

    //=============================================================================================
    // Rule
    //=============================================================================================
    new CfnRule(this, 'AdminUserEmailValidation', {
      ruleCondition: Fn.conditionEquals(shouldDeployWebUI.valueAsString, 'yes'),
      assertions: [
        {
          assert: Fn.conditionNot(Fn.conditionEquals(adminUserEmail.valueAsString, '')),
          assertDescription: 'AdminUserEmail is required when Web UI deployment is enabled',
        },
      ],
    });

    // Collect Deployment Metrics
    const metricsResources = new MetricResources(this, 'MetricResources', {
      solutionTMN: props.solutionTMN,
      solutionVersion: props.solutionVersion,
      solutionId: props.solutionId,
      runtimePython: props.runtimePython,
      solutionsBucket: sourceCodeBucket,
      lambdaLayer: asrLambdaLayer,
    });

    /**
     * @description sendNotifications - send notifications and log messages from Orchestrator step function
     * @type {lambda.Function}
     */
    const sendNotifications = new lambda.Function(this, 'sendNotifications', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-sendNotifications',
      handler: 'send_notifications.lambda_handler',
      runtime: props.runtimePython,
      description: 'Sends notifications and log messages',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'send_notifications.zip'),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
        ENHANCED_METRICS: enableEnhancedCloudWatchMetrics.valueAsString,
        FINDINGS_TABLE_NAME: asrFindingsTable.tableName,
        HISTORY_TABLE_NAME: remediationHistoryTable.tableName,
        HISTORY_TTL_DAYS: historyTTL,
        POWERTOOLS_SERVICE_NAME: 'send_notifications',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
        SECURITY_HUB_V2_ENABLED: metricsResources.securityHubV2Enabled,
        DISABLE_ACCOUNT_ALIAS_LOOKUP: 'false',
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: notifyRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = sendNotifications.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency due to low request rate',
            },
          ],
        },
      };
    }

    //-------------------------------------------------------------------------
    // Custom Lambda Policy
    //
    const createCustomActionPolicy = new Policy(this, 'createCustomActionPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Custom_Action',
      statements: [
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: [
            'securityhub:CreateActionTarget',
            'securityhub:DescribeActionTargets',
            'securityhub:DeleteActionTarget',
          ],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter', 'ssm:DeleteParameter'],
          resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`],
        }),
      ],
    });

    const createCAPolicyResource = createCustomActionPolicy.node.findChild('Resource') as CfnPolicy;

    createCAPolicyResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W12',
            reason: 'Resource * is required for CloudWatch Logs policies used on Lambda functions.',
          },
        ],
      },
    };

    //-------------------------------------------------------------------------
    // Custom Lambda Role
    //
    const createCustomActionRole = new Role(this, 'createCustomActionRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to allow creation of Security Hub Custom Actions',
    });

    createCustomActionRole.attachInlinePolicy(createCustomActionPolicy);

    const createCARoleResource = createCustomActionRole.node.findChild('Resource') as CfnRole;

    createCARoleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W28',
            reason: 'Static names chosen intentionally to provide easy integration with playbook templates',
          },
        ],
      },
    };

    //-------------------------------------------------------------------------
    // Custom Lambda - Create Custom Action
    //
    const createCustomAction = new lambda.Function(this, 'CreateCustomAction', {
      functionName: RESOURCE_NAME_PREFIX + '-SHARR-CustomAction',
      handler: 'action_target_provider.lambda_handler',
      runtime: props.runtimePython,
      description: 'Custom resource to create or retrieve an action target in Security Hub',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'action_target_provider.zip'),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        POWERTOOLS_SERVICE_NAME: 'action_target_provider',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: createCustomActionRole,
      layers: [asrLambdaLayer],
    });

    const createCAFuncResource = createCustomAction.node.findChild('Resource') as lambda.CfnFunction;

    createCAFuncResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W58',
            reason: 'False positive. the lambda role allows write to CW Logs',
          },
          {
            id: 'W89',
            reason: 'There is no need to run this lambda in a VPC',
          },
          {
            id: 'W92',
            reason: 'There is no need for Reserved Concurrency due to low request rate',
          },
        ],
      },
    };

    //---------------------------------------------------------------------
    // Scheduling Queue for SQS Remediation Throttling
    //
    const deadLetterQueue = new sqs.Queue(this, 'deadLetterSchedulingQueue', {
      encryption: sqs.QueueEncryption.KMS,
      enforceSSL: true,
      encryptionMasterKey: kmsKey,
    });

    const deadLetterQueueDeclaration: sqs.DeadLetterQueue = {
      maxReceiveCount: 10,
      queue: deadLetterQueue,
    };

    const schedulingQueue = new sqs.Queue(this, 'SchedulingQueue', {
      encryption: sqs.QueueEncryption.KMS,
      enforceSSL: true,
      deadLetterQueue: deadLetterQueueDeclaration,
      encryptionMasterKey: kmsKey,
    });

    const eventSource = new lambdaEventSources.SqsEventSource(schedulingQueue, {
      batchSize: 1,
    });

    const orchestrator = new OrchestratorConstruct(this, 'orchestrator', {
      roleArn: orchestratorRole.roleArn,
      ssmDocStateLambda: checkSSMDocumentState.functionArn,
      ssmExecDocLambda: execAutomation.functionArn,
      ssmExecMonitorLambda: monitorSSMExecState.functionArn,
      notifyLambda: sendNotifications.functionArn,
      getApprovalRequirementLambda: getApprovalRequirement.functionArn,
      solutionId: RESOURCE_NAME_PREFIX,
      solutionName: props.solutionName,
      solutionVersion: props.solutionVersion,
      orchLogGroup: props.orchestratorLogGroup,
      kmsKeyParm: kmsKeyParm,
      sqsQueue: schedulingQueue,
      timeoutHours: orchestratorTimeoutHours,
    });

    sendNotifications.addPermission('AllowExecutionFailureRuleInvoke', {
      principal: new ServicePrincipal('events.amazonaws.com'),
      action: 'lambda:InvokeFunction',
      sourceArn: orchestrator.executionFailureRuleArn,
    });

    const orchStateMachine = orchestrator.node.findChild('StateMachine') as StateMachine;
    const stateMachineConstruct = orchStateMachine.node.defaultChild as CfnStateMachine;
    const orchArnParm = orchestrator.node.findChild('SHARR_Orchestrator_Arn') as StringParameter;
    const orchestratorArn = orchArnParm.node.defaultChild as CfnParameter;

    if (enableAdaptiveConcurrency) {
      //---------------------------------------------------------------------
      // Custom Resource to Enable SSM Adaptive Concurrency
      //---------------------------------------------------------------------
      const enableAdaptiveConcurrencyRole = new Role(this, 'EnableAdaptiveConcurrencyRole', {
        assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
        description: 'Lambda role to enable SSM Adaptive Concurrency',
      });

      enableAdaptiveConcurrencyRole.addToPolicy(
        new PolicyStatement({
          actions: ['ssm:UpdateServiceSetting', 'ssm:GetServiceSetting'],
          resources: [
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:servicesetting/ssm/automation/enable-adaptive-concurrency`,
          ],
        }),
      );

      const enableAdaptiveConcurrencyFunctionName = RESOURCE_NAME_PREFIX + '-EnableSSMAdaptiveConcurrency';
      const enableAdaptiveConcurrencyLogGroupName = `/aws/lambda/${enableAdaptiveConcurrencyFunctionName}`;
      enableAdaptiveConcurrencyRole.addToPolicy(
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [
            `arn:${stack.partition}:logs:${stack.region}:${stack.account}:log-group:${enableAdaptiveConcurrencyLogGroupName}`,
            `arn:${stack.partition}:logs:${stack.region}:${stack.account}:log-group:${enableAdaptiveConcurrencyLogGroupName}:*`,
          ],
        }),
      );

      const enableAdaptiveConcurrencyLambda = new lambda.Function(this, 'EnableAdaptiveConcurrencyLambda', {
        functionName: enableAdaptiveConcurrencyFunctionName,
        handler: 'enable_adaptive_concurrency.lambda_handler',
        runtime: props.runtimePython,
        description: 'Custom resource to enable SSM Adaptive Concurrency',
        code: getLambdaCode(
          sourceCodeBucket,
          props.solutionTMN,
          props.solutionVersion,
          'enable_adaptive_concurrency.zip',
        ),
        timeout: Duration.minutes(5),
        role: enableAdaptiveConcurrencyRole,
      });

      addCfnGuardSuppression(enableAdaptiveConcurrencyLambda, 'LAMBDA_INSIDE_VPC');
      addCfnGuardSuppression(enableAdaptiveConcurrencyLambda, 'LAMBDA_CONCURRENCY_CHECK');

      new CustomResource(this, 'EnableAdaptiveConcurrencyResource', {
        serviceToken: enableAdaptiveConcurrencyLambda.functionArn,
        properties: {
          SolutionVersion: props.solutionVersion,
        },
      });
    }

    // Role used by custom action EventBridge rules
    const customActionEventsRuleRole = new Role(this, 'EventsRuleRole', {
      assumedBy: new ServicePrincipal('events.amazonaws.com'),
    });

    //---------------------------------------------------------------------
    // S3 Bucket for CSV Export Files
    //
    const accessLogsBucket = new s3.Bucket(this, 'CSVExportAccessLogs', {
      objectOwnership: s3.ObjectOwnership.OBJECT_WRITER,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });
    addCfnGuardSuppression(accessLogsBucket, 'S3_BUCKET_LOGGING_ENABLED');

    const csvExportBucket = new Bucket(this, 'CSVExportBucket', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: kmsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      serverAccessLogsBucket: accessLogsBucket,
      lifecycleRules: [
        {
          id: 'DeleteOldCSVExports',
          enabled: true,
          expiration: cdk.Duration.days(exportFilesTTL), // Auto-delete CSV files after 30 days
        },
      ],
    });

    const webUINestedStack = new WebUINestedStack(this, 'WebUINestedStack', {
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTMN,
      solutionsBucket: sourceCodeBucket,
      resourceNamePrefix: RESOURCE_NAME_PREFIX,
      findingsTable: asrFindingsTable.tableArn,
      remediationHistoryTable: remediationHistoryTable.tableArn,
      apiFunctionName: apiFunctionName,
      stackName: cdk.Stack.of(this).stackName,
      adminUserEmail: adminUserEmail.valueAsString,
      orchestratorArn: orchStateMachine.stateMachineArn,
      kmsKeyARN: kmsKey.keyArn,
      csvExportBucket: csvExportBucket,
      presignedUrlTTLDays: presignedUrlTTL,
      ticketingGenFunction: orchestrator.ticketGenFunctionNameParamValue,
      securityHubV2Enabled: metricsResources.securityHubV2Enabled,
    });

    const webUINestedStackResource = webUINestedStack.nestedStackResource as cdk.CfnResource;
    webUINestedStackResource.cfnOptions.condition = webUIEnabled;

    // Add property override for WebUI template URL
    webUINestedStackResource.addPropertyOverride(
      'TemplateURL',
      'https://' +
        Fn.findInMap('SourceCode', 'General', 'S3Bucket') +
        '-reference.s3.amazonaws.com/' +
        Fn.findInMap('SourceCode', 'General', 'KeyPrefix') +
        '/automated-security-response-webui-nested-stack.template',
    );

    //---------------------------------------------------------------------
    // Remediation Configuration Table - Stores remediation settings per control
    //
    const remediationConfigTable = new Table(this, 'RemediationConfigTable', {
      partitionKey: { name: 'controlId', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.DEFAULT, // service-managed encryption
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    addCfnGuardSuppression(remediationConfigTable, 'DYNAMODB_TABLE_ENCRYPTED_KMS'); // table is encrypted using service-managed encryption

    //---------------------------------------------------------------------
    // Synchronization Findings Construct
    //
    const synchronizationConstruct = new SynchronizationFindingsConstruct(this, 'SynchronizationFindingsConstruct', {
      solutionId: props.solutionId,
      solutionTMN: props.solutionTMN,
      solutionVersion: props.solutionVersion,
      resourceNamePrefix: RESOURCE_NAME_PREFIX,
      sourceCodeBucket,
      findingsTable: asrFindingsTable.tableArn,
      kmsKey,
      findingsTTL,
      remediationConfigTable: remediationConfigTable.tableArn,
    });

    //---------------------------------------------------------------------
    // Custom Resource to trigger initial synchronization when WebUI is deployed
    //
    const initialSyncTrigger = new CustomResource(this, 'InitialSynchronizationTrigger', {
      serviceToken: synchronizationConstruct.customResourceProvider.functionArn,
      properties: {
        TriggerReason: 'WebUI deployment completed',
      },
    });

    // Only create the custom resource when WebUI is enabled
    const initialSyncTriggerResource = initialSyncTrigger.node.defaultChild as cdk.CfnResource;
    initialSyncTriggerResource.cfnOptions.condition = webUIEnabled;

    // Ensure the custom resource is created after the WebUI nested stack
    initialSyncTrigger.node.addDependency(webUINestedStack);

    //---------------------------------------------------------------------
    // OneTrigger - Remediate with ASR custom action
    //
    // Create an IAM role for Events to start the State Machine

    new OneTrigger(this, 'RemediateWithSharr', {
      targetArn: orchStateMachine.stateMachineArn,
      serviceToken: createCustomAction.functionArn,
      ruleId: 'Remediate Custom Action',
      ruleName: 'Remediate_with_ASR_CustomAction',
      eventsRole: customActionEventsRuleRole,
      customActionName: 'Remediate with ASR', // must be <= 20 chars in length
      customActionId: 'ASRRemediation', // must be <= 20 chars in length
      customActionDescription: 'Submit the finding to Automated Response and Remediation (ASR) for remediation.',
      prereq: [createCAFuncResource, createCAPolicyResource],
    });

    //---------------------------------------------------------------------
    // OneTrigger - Remediate & Generate Ticket custom action
    //
    new OneTrigger(this, 'RemediateAndTicket', {
      targetArn: orchStateMachine.stateMachineArn,
      serviceToken: createCustomAction.functionArn,
      condition: orchestrator.ticketingEnabled,
      ruleId: 'Ticketing Custom Action',
      description: 'Remediate with ASR and generate a ticket.',
      ruleName: 'ASR_Remediate_and_Ticket_CustomAction',
      eventsRole: customActionEventsRuleRole,
      customActionName: 'ASR:Remediate&Ticket', // must be <= 20 chars in length
      customActionId: 'ASRTicketing', // must be <= 20 chars in length
      customActionDescription:
        'Submit the finding to Automated Response and Remediation (ASR) for remediation and generate a ticket.',
      prereq: [createCAFuncResource, createCAPolicyResource],
    });

    //-------------------------------------------------------------------------
    // Loop through all of the Playbooks and create an option to load each
    //
    const securityStandardPlaybookNames: string[] = [];
    standardPlaybookProps.forEach((playbookProps) => {
      const playbook = new AdminPlaybook(this, {
        name: playbookProps.name,
        stackDependencies: [stateMachineConstruct, orchestratorArn],
        defaultState: playbookProps.defaultParameterValue,
        description: playbookProps.description,
      });
      securityStandardPlaybookNames.push(playbook.parameterName);
    });

    const scPlaybook = new AdminPlaybook(this, {
      name: scPlaybookProps.name,
      stackDependencies: [stateMachineConstruct, orchestratorArn],
      defaultState: scPlaybookProps.defaultParameterValue,
      description: scPlaybookProps.description,
    });

    //---------------------------------------------------------------------
    // Scheduling Table for SQS Remediation Throttling
    //
    const schedulingTable = new Table(this, 'SchedulingTable', {
      partitionKey: { name: 'AccountID-Region', type: AttributeType.STRING },
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      timeToLiveAttribute: 'TTL',
      deletionProtection: true,
    });
    const readScaling = schedulingTable.autoScaleReadCapacity({ minCapacity: 1, maxCapacity: 10 });
    readScaling.scaleOnUtilization({
      targetUtilizationPercent: 70,
    });
    const writeScaling = schedulingTable.autoScaleWriteCapacity({ minCapacity: 1, maxCapacity: 10 });
    writeScaling.scaleOnUtilization({
      targetUtilizationPercent: 70,
    });

    addCfnGuardSuppression(schedulingTable, 'DYNAMODB_BILLING_MODE_RULE');
    addCfnGuardSuppression(schedulingTable, 'DYNAMODB_TABLE_ENCRYPTED_KMS');

    const schedulingLamdbdaPolicy = new Policy(this, 'SchedulingLambdaPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Scheduling_Lambda',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
      ],
    });

    const schedulingLambdaRole = new Role(this, 'SchedulingLambdaRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to schedule remediations that are sent to SQS through the orchestrator',
    });

    schedulingLambdaRole.attachInlinePolicy(schedulingLamdbdaPolicy);

    /**
     * @description schedulingLambdaTrigger - Lambda trigger for SQS Queue
     * @type {lambda.Function}
     */
    const schedulingLambdaTrigger = new lambda.Function(this, 'schedulingLambdaTrigger', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-schedulingLambdaTrigger',
      handler: 'schedule_remediation.lambda_handler',
      runtime: props.runtimePython,
      description: 'SO0111 ASR function that schedules remediations in member accounts',
      code: getLambdaCode(sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'schedule_remediation.zip'),
      environment: {
        SchedulingTableName: schedulingTable.tableName,
        RemediationWaitTime: '3',
        POWERTOOLS_SERVICE_NAME: 'schedule_remediation',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      role: schedulingLambdaRole,
      reservedConcurrentExecutions: 1,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });
    orchStateMachine.grantTaskResponse(schedulingLambdaTrigger);
    schedulingTable.grantReadWriteData(schedulingLambdaTrigger);

    addCfnGuardSuppression(schedulingLambdaTrigger, 'LAMBDA_INSIDE_VPC');

    schedulingLambdaTrigger.addEventSource(eventSource);

    new ActionLog(this, 'ActionLog', {
      logGroupName: props.cloudTrailLogGroupName,
    });

    //---------------------------------------------------------------------
    // Pre-processor Components
    //
    const preProcessorConstruct = new PreProcessorConstruct(this, 'PreProcessorConstruct', {
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      resourceNamePrefix: RESOURCE_NAME_PREFIX,
      solutionsBucket: sourceCodeBucket,
      solutionTMN: props.solutionTMN,
      findingsTable: asrFindingsTable.tableArn,
      remediationHistoryTable: remediationHistoryTable.tableArn,
      functionName: preProcessorFunctionName,
      remediationConfigTable: remediationConfigTable.tableArn,
      orchestratorArn: orchStateMachine.stateMachineArn,
      findingsTTL,
      historyTTL,
      kmsKey,
    });

    //---------------------------------------------------------------------
    // Trigger - Rule to capture all finding events for Pre-processor
    //

    new Trigger(this, 'FindingEventsTrigger', {
      targetArn: preProcessorConstruct.queue.queueArn,
      solutionTMN: props.solutionTMN,
      solutionId: props.solutionId,
    });

    //-------------------------------------------------------------------------
    // Custom Resource for Remediation Configuration Table Population
    //
    const remediationConfigPolicy = new Policy(this, 'RemediationConfigPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Remediation_Config',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: [
            'dynamodb:PutItem',
            'dynamodb:UpdateItem',
            'dynamodb:DeleteItem',
            'dynamodb:Scan',
            'dynamodb:BatchWriteItem',
          ],
          resources: [remediationConfigTable.tableArn],
        }),
        new PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [
            `arn:${this.partition}:s3:::${solutionsReferenceBucket}/${props.solutionTMN}/${props.solutionVersion}/*`,
            `arn:${this.partition}:s3:::${solutionsReferenceBucket}-cn/${props.solutionTMN}/${props.solutionVersion}/*`,
            `arn:${this.partition}:s3:::${solutionsReferenceBucket}-us-gov/${props.solutionTMN}/${props.solutionVersion}/*`,
          ],
        }),
      ],
    });

    const remediationConfigRole = new Role(this, 'RemediationConfigRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for remediation configuration table population',
    });

    remediationConfigRole.attachInlinePolicy(remediationConfigPolicy);

    const remediationConfigProvider = new lambda.Function(this, 'RemediationConfigProvider', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-RemediationConfigProvider',
      handler: 'remediation_config_provider.lambda_handler',
      runtime: props.runtimePython,
      description: 'Custom resource to populate remediation configuration table',
      code: getLambdaCode(
        sourceCodeBucket,
        props.solutionTMN,
        props.solutionVersion,
        'remediation_config_provider.zip',
      ),
      environment: {
        POWERTOOLS_SERVICE_NAME: 'action_target_provider',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
        REFERENCE_BUCKET_NAME: solutionsReferenceBucket,
        REFERENCE_BUCKET_PARTITION: solutionsReferenceBucketPartition,
        CUSTOM_REFERENCE_BUCKET_REGION: customReferenceBucketRegion,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      tracing: Tracing.ACTIVE,
      timeout: Duration.seconds(300),
      layers: [asrLambdaLayer],
      role: remediationConfigRole,
    });
    addCfnGuardSuppression(remediationConfigProvider, 'LAMBDA_INSIDE_VPC'); // custom resource lambda - does not need to be inside VPC
    addCfnGuardSuppression(remediationConfigProvider, 'LAMBDA_CONCURRENCY_CHECK'); // Ccstom resource lambda - does not need concurrency set

    const remediationConfigResource = new CustomResource(this, 'RemediationConfigResource', {
      serviceToken: remediationConfigProvider.functionArn,
      properties: {
        TableName: remediationConfigTable.tableName,
        SolutionVersion: props.solutionVersion, // Triggers update when version changes
      },
    });

    remediationConfigResource.node.addDependency(remediationConfigTable);

    const cloudWatchMetrics = new CloudWatchMetrics(this, {
      solutionId: props.solutionId,
      schedulingQueueName: schedulingQueue.queueName,
      orchStateMachineArn: orchStateMachine.stateMachineArn,
      kmsKey: kmsKey,
      actionLogLogGroupName: props.cloudTrailLogGroupName,
      enhancedMetricsEnabled: enhancedMetricsEnabled,
      webUIEnabled: webUIEnabled,
      userPoolId: webUINestedStack.userPoolId,
      preProcessorDLQName: preProcessorConstruct.deadLetterQueue.queueName,
      synchronizationLambdaName: synchronizationConstruct.synchronizationLambda.functionName,
    });

    const sortedPlaybookNames = [...securityStandardPlaybookNames].sort();

    stack.templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'Consolidated Control Findings Playbook' },
            Parameters: [scPlaybook.parameterName],
          },
          {
            Label: { default: 'Security Standard Playbooks' },
            Parameters: sortedPlaybookNames,
          },
          {
            Label: { default: 'Orchestrator Configuration' },
            Parameters: ['ReuseOrchestratorLogGroup'],
          },
          {
            Label: { default: 'Web UI Configuration' },
            Parameters: [shouldDeployWebUI.logicalId, adminUserEmail.logicalId],
          },
          {
            Label: { default: 'CloudWatch Metrics' },
            Parameters: [...cloudWatchMetrics.getStandardParameterIds()],
          },
          {
            Label: { default: '(Optional) Enhanced CloudWatch Metrics' },
            Parameters: [enableEnhancedCloudWatchMetrics.logicalId, ...cloudWatchMetrics.getEnhancedParameterIds()],
          },
          {
            Label: { default: '(Optional) Ticketing Service Integration' },
            Parameters: [orchestrator.ticketGenFunctionNameParamId],
          },
        ],
        ParameterLabels: {
          SecurityStandardPlaybooks: {
            default:
              'For more details see: https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/enable-fully-automated-remediations.html',
          },
        },
      },
    };

    new CfnOutput(this, 'Generated Ticketing Lambda function ARN', {
      description:
        'The Lambda ARN constructed from the Ticket Generator Function Name you have provided as input to the stack. ' +
        'This ARN is used by the solution to plug your ticketing function into the Orchestrator step function. ' +
        'This field will be empty if you did not provide a ticketing Lambda Function name.',
      value: orchestrator.ticketGenFunctionARN,
    });

    new CfnOutput(this, 'ASR Findings DynamoDB Table', {
      description: 'Table used to store findings that ASR supports for remediation.',
      value: asrFindingsTable.tableName,
    });

    new CfnOutput(this, 'Remediation Configuration DynamoDB Table', {
      description: 'Table used to control the enablement of automatic remediations for a given control.',
      value: remediationConfigTable.tableName,
    });

    new CfnOutput(this, 'User Account Mapping DynamoDB Table', {
      description: 'Table used to store user account access permissions for Account Operator users.',
      value: webUINestedStack.userAccountMappingTableARN,
      condition: webUIEnabled,
    });

    new CfnOutput(this, 'WebUIURL', {
      description: 'URL for the Web UI',
      value: `https://${webUINestedStack.distributionDomainName}`,
      condition: webUIEnabled,
    });

    new CfnOutput(this, 'APIEndpoint', {
      description: 'API Gateway endpoint URL',
      value: webUINestedStack.api.url,
      condition: webUIEnabled,
    });

    new CfnOutput(this, 'UserPoolId', {
      description: 'Cognito User Pool ID for the Web UI',
      value: webUINestedStack.userPoolId,
      condition: webUIEnabled,
    });
  }
}

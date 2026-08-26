// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { CfnPolicy, CfnRole, Effect, Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Runtime, Tracing, CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { Rule, Schedule } from 'aws-cdk-lib/aws-events';
import { SfnStateMachine } from 'aws-cdk-lib/aws-events-targets';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from './cdk-helper/log-group';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { CfnParameter, Duration, Stack } from 'aws-cdk-lib';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import * as cdk from 'aws-cdk-lib';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import { LambdaInvoke } from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { SynchronizationFindingsEnvironmentConfig } from '@asr/data-models';

export interface SynchronizationFindingsConstructProps {
  readonly solutionId: string;
  readonly solutionTMN: string;
  readonly solutionVersion: string;
  readonly resourceNamePrefix: string;
  readonly sourceCodeBucket: IBucket;
  readonly findingsTable: ITable;
  readonly kmsKey: IKey;
  readonly findingsTTL: string;
  readonly remediationConfigTable: ITable;
  readonly resourceFiltersTable: ITable;
  readonly notificationConfigTable: ITable;
}

export class SynchronizationFindingsConstruct extends Construct {
  public readonly synchronizationLambda: lambda.Function;
  public readonly synchronizationRole: Role;
  public readonly customResourceProvider: lambda.Function;
  public readonly sweepStateMachine: sfn.StateMachine;

  constructor(scope: Construct, id: string, props: SynchronizationFindingsConstructProps) {
    super(scope, id);

    const stack = Stack.of(this);

    //---------------------------------------------------------------------
    // Synchronization Lambda Role and Policy
    //---------------------------------------------------------------------
    const synchronizationPolicy = new Policy(this, 'synchronizationPolicy', {
      policyName: props.resourceNamePrefix + '-ASR_Synchronization',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['securityhub:GetFindings'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [props.kmsKey.keyArn],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:PutParameter'],
          resources: [
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${props.solutionId}/anonymous_metrics_uuid`,
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${props.solutionId}/metrics_uuid`,
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${props.solutionId}/version`,
          ],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameters', 'ssm:GetParameter', 'ssm:GetParametersByPath'],
          resources: [`arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/Solutions/SO0111/*`],
          effect: Effect.ALLOW,
        }),
        new PolicyStatement({
          actions: ['organizations:ListParents', 'organizations:DescribeAccount'],
          resources: ['*'],
          effect: Effect.ALLOW,
        }),
        //-------------------------------------------------------------------
        // Account-aware synchronization permission
        // The sweep state machine drives the per-account fan-out and the resume
        // loop; the Lambda only ever runs one account slice per invocation and
        // never invokes itself, so no lambda:InvokeFunction grant is needed here.
        // Enumerate the Security Hub member accounts to synchronize. Runs in the
        // aggregation account; ListMembers does not support resource-level
        // scoping, so the resource is '*'.
        //-------------------------------------------------------------------
        new PolicyStatement({
          actions: ['securityhub:ListMembers'],
          resources: ['*'],
          effect: Effect.ALLOW,
        }),
      ],
    });

    {
      const childToMod = synchronizationPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for CloudWatch Logs policies used by synchronization Lambda function.',
            },
          ],
        },
      };
    }

    this.synchronizationRole = new Role(this, 'synchronizationRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for ASR synchronization function',
      roleName: `${props.resourceNamePrefix}-ASR-Synchronization`,
    });

    this.synchronizationRole.attachInlinePolicy(synchronizationPolicy);

    {
      const childToMod = this.synchronizationRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide easy integration with synchronization function.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(this.synchronizationRole, 'IAM_NO_INLINE_POLICY_CHECK');

    //---------------------------------------------------------------------
    // Synchronization Lambda Function
    //---------------------------------------------------------------------
    this.synchronizationLambda = new lambda.Function(this, 'SynchronizationFindingsLambda', {
      functionName: props.resourceNamePrefix + '-ASR-SynchronizationFindingsLambda',
      logGroup: createLogGroup(this, 'SynchronizationFindingsLambdaLogGroup'),
      handler: 'synchronization/synchronizationHandler.handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'Synchronization findings lambda',
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'synchronization_findings',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        FINDINGS_TABLE_NAME: props.findingsTable.tableName,
        REMEDIATION_CONFIG_TABLE_NAME: props.remediationConfigTable.tableName,
        RESOURCE_FILTERS_TABLE_NAME: props.resourceFiltersTable.tableName,
        NOTIFICATION_CONFIG_TABLE_NAME: props.notificationConfigTable.tableName,
        FINDINGS_TTL_DAYS: props.findingsTTL,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      } satisfies SynchronizationFindingsEnvironmentConfig,
      memorySize: 512,
      timeout: Duration.minutes(15),
      role: this.synchronizationRole,
      tracing: Tracing.ACTIVE,
    });

    {
      const childToMod = this.synchronizationLambda.node.findChild('Resource') as CfnFunction;
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

    props.findingsTable.grantReadWriteData(this.synchronizationLambda);

    props.remediationConfigTable.grantReadWriteData(this.synchronizationLambda);

    props.resourceFiltersTable.grantReadData(this.synchronizationLambda);

    props.notificationConfigTable.grantReadData(this.synchronizationLambda);

    // The sweep state machine is defined later in this constructor, but the trigger needs its ARN now
    // (for the StartExecution grant and env var). Build it from the static name to avoid reordering the
    // constructor or a circular dependency.
    const sweepStateMachineName = `${props.resourceNamePrefix}-ASR-SynchronizationSweep`;
    const sweepStateMachineArn = `arn:${stack.partition}:states:${stack.region}:${stack.account}:stateMachine:${sweepStateMachineName}`;

    //---------------------------------------------------------------------
    // Custom Resource Provider Lambda for Initial Synchronization Trigger
    //---------------------------------------------------------------------
    const customResourcePolicy = new Policy(this, 'CustomResourcePolicy', {
      policyName: props.resourceNamePrefix + '-ASR_SynchronizationTrigger',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*`],
        }),
        // Start exactly one state machine — the sync sweep — scoped to its ARN, not '*'.
        new PolicyStatement({
          actions: ['states:StartExecution'],
          resources: [sweepStateMachineArn],
        }),
      ],
    });

    {
      const childToMod = customResourcePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for CloudWatch Logs policies used by custom resource Lambda function.',
            },
          ],
        },
      };
    }
    const customResourceRole = new Role(this, 'customResourceRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for ASR synchronization trigger custom resource',
      roleName: `${props.resourceNamePrefix}-ASR-SynchronizationTrigger`,
    });

    customResourceRole.attachInlinePolicy(customResourcePolicy);

    {
      const childToMod = customResourceRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide easy integration with synchronization trigger.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(customResourceRole, 'IAM_NO_INLINE_POLICY_CHECK');

    this.customResourceProvider = new lambda.Function(this, 'SynchronizationTriggerProvider', {
      functionName: props.resourceNamePrefix + '-ASR-SynchronizationTriggerProvider',
      logGroup: createLogGroup(this, 'SynchronizationTriggerProviderLogGroup'),
      handler: 'synchronization/customResourceHandler.handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'Custom resource provider to trigger initial synchronization',
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'synchronization_trigger',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        SYNCHRONIZATION_STATE_MACHINE_ARN: sweepStateMachineArn,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 128,
      timeout: Duration.minutes(5),
      role: customResourceRole,
      tracing: Tracing.ACTIVE,
    });

    {
      const childToMod = this.customResourceProvider.node.findChild('Resource') as CfnFunction;
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
    addCfnGuardSuppression(this.customResourceProvider, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.customResourceProvider, 'LAMBDA_CONCURRENCY_CHECK');

    //---------------------------------------------------------------------
    // Synchronization Sweep State Machine (sequential account fan-out)
    //
    // A "sweep" is one end-to-end synchronization that imports every finding from AWS Security Hub
    // across all member accounts.
    //
    // Drives the whole-fleet sync one account at a time:
    //   Enumerate accounts -> Map(concurrency 1) over accounts -> Mark sweep done.
    // The Map is intentionally sequential (MaxConcurrency 1): the sync Lambda's
    // pacing is tuned against the Security Hub GetFindings rate limit, so running
    // two account slices at once would throttle. Each Map branch runs one
    // account's slice and, because a single large account may not drain in one
    // 15-minute invocation, loops back to the SAME account until it reports done
    // (the slice checkpoints its own cursor between invocations).
    //
    // Circuit breaker: the loop is bounded by a per-account attempt counter that
    // lives in the state and is decremented by a pure Step Functions intrinsic
    // (States.MathAdd) — NOT by the Lambda. So even if a Lambda bug made a slice
    // report "not done, made progress" forever, the branch still stops after
    // SyncMaxAttemptsPerAccount invocations. This deliberately does not trust the
    // Lambda's cursor/DynamoDB logic; it is the backstop for when that logic fails.
    //---------------------------------------------------------------------
    const maxAttemptsPerAccount = new CfnParameter(this, 'SyncMaxAttemptsPerAccount', {
      type: 'Number',
      description:
        'Circuit breaker: the maximum number of times the import of security findings re-runs a single account before ' +
        'giving up on that account for this run. Each slice imports up to ~10k findings, so the default ' +
        'of 5 covers >50k findings per account. Raise it only for accounts with an exceptionally large ' +
        'backlog.',
      default: 5,
      minValue: 1,
      maxValue: 100,
    });

    const invokeSyncLambda = (id: string, payload: Record<string, unknown>, resultPath?: string) =>
      new LambdaInvoke(this, id, {
        lambdaFunction: this.synchronizationLambda,
        payload: sfn.TaskInput.fromObject(payload),
        // The Lambda returns the plain task result (invoked with payloadResponseOnly). For the enumerate
        // and mark-done tasks that result IS the state output. For the per-account slice we instead land
        // it under a resultPath so the top-level attempt counter it sits beside is preserved across the
        // resume loop.
        payloadResponseOnly: true,
        ...(resultPath ? { resultPath } : {}),
      });

    const enumerateAccounts = invokeSyncLambda('EnumerateAccounts', { task: 'enumerate-accounts' });

    // One Map branch per account: run a slice (result under $.slice), decrement the attempt counter, then
    // either loop the same account, complete it, trip the breaker, or tolerate a stall.
    const runAccountSlice = invokeSyncLambda(
      'RunAccountSlice',
      { task: 'sync-account-slice', 'accountId.$': '$.accountId' },
      '$.slice',
    );

    // Decrement the per-account attempt counter with a Step Functions intrinsic — no Lambda involvement,
    // so this remains a true circuit breaker even if the slice Lambda misbehaves. accountId and the slice
    // result are carried forward unchanged so the Choice can still read them.
    const decrementAttempts = new sfn.Pass(this, 'DecrementAttempts', {
      parameters: {
        'accountId.$': '$.accountId',
        'attemptsRemaining.$': 'States.MathAdd($.attemptsRemaining, -1)',
        'slice.$': '$.slice',
      },
    });

    const accountSliceComplete = new sfn.Pass(this, 'AccountSliceComplete');

    // One bad account must not sink the whole sweep. The inline Map cannot express
    // ToleratedFailurePercentage (a Distributed-Map-only property), so we get the same effect —
    // tolerate every per-account failure — by ending each branch in a success Pass instead of a Fail
    // and catching any surviving Lambda error into it. The account's own cursor still records that it
    // did not finish, so the derived progress count stays truthful and the next run retries it.
    const accountSliceTolerated = new sfn.Pass(this, 'AccountSliceTolerated');

    // The circuit breaker tripped: the account used up all its attempts without reporting done. Kept as a
    // distinct success state (not merged into Tolerated) so a tripped breaker is visible in the execution
    // history and metrics. The account is left not-done for the next run, exactly like a tolerated stall.
    const accountSliceExhausted = new sfn.Pass(this, 'AccountSliceExhausted');

    const evaluateAccountSlice = new sfn.Choice(this, 'AccountDone?')
      // Done wins first: a final slice that finishes counts as complete even if it used the last attempt.
      .when(sfn.Condition.booleanEquals('$.slice.done', true), accountSliceComplete)
      // Circuit breaker: out of attempts and still not done — stop, do not loop again.
      .when(sfn.Condition.numberLessThanEquals('$.attemptsRemaining', 0), accountSliceExhausted)
      // Not done but still importing findings/controls, and attempts remain: resume the SAME account.
      .when(sfn.Condition.booleanEquals('$.slice.madeProgress', true), runAccountSlice)
      // Not done and no progress: stop this branch (do not loop) but tolerate it — the account is left
      // not-done for the next run rather than failing the sweep.
      .otherwise(accountSliceTolerated);

    // A Lambda error that outlives the retries is tolerated too, for the same reason.
    runAccountSlice.addCatch(accountSliceTolerated, { errors: ['States.ALL'] });
    runAccountSlice.next(decrementAttempts);
    decrementAttempts.next(evaluateAccountSlice);

    const syncAccountsMap = new sfn.Map(this, 'SyncAccountsSequentially', {
      comment: 'Sync each member account one at a time to stay under the Security Hub GetFindings rate limit',
      itemsPath: '$.accountIds',
      // Strictly sequential: parallel slices would exceed the Security Hub rate limit the Lambda is paced
      // against. Seed each account with its own attempt counter for the circuit breaker.
      maxConcurrency: 1,
      itemSelector: { 'accountId.$': '$$.Map.Item.Value', 'attemptsRemaining.$': '$.maxAttempts' },
    });
    syncAccountsMap.itemProcessor(runAccountSlice);

    const markSweepDone = invokeSyncLambda('MarkSweepDone', { task: 'mark-sweep-done' });

    // Inject the per-account attempt cap (a stack parameter) into the state input so each Map item can
    // seed its own counter from it.
    const injectAttempts = new sfn.Pass(this, 'InjectAttempts', {
      parameters: {
        'accountIds.$': '$.accountIds',
        'totalAccounts.$': '$.totalAccounts',
        maxAttempts: maxAttemptsPerAccount.valueAsNumber,
      },
    });

    const definition = enumerateAccounts.next(injectAttempts).next(syncAccountsMap).next(markSweepDone);

    // The StateMachine L2 construct grants this role lambda:InvokeFunction scoped to the exact function
    // its LambdaInvoke tasks target (the synchronization Lambda), plus the X-Ray grants tracing needs —
    // so the role's permissions are minimal and account-slice-scoped without a manual statement.
    const sweepStateMachineRole = new Role(this, 'SweepStateMachineRole', {
      assumedBy: new ServicePrincipal('states.amazonaws.com'),
      description: 'Execution role for the ASR synchronization sweep state machine',
      roleName: `${props.resourceNamePrefix}-ASR-SynchronizationSweep`,
    });
    {
      const childToMod = sweepStateMachineRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static name chosen intentionally so the trigger can reference the sweep state machine.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(sweepStateMachineRole, 'IAM_NO_INLINE_POLICY_CHECK');

    this.sweepStateMachine = new sfn.StateMachine(this, 'SynchronizationSweepStateMachine', {
      stateMachineName: sweepStateMachineName,
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      role: sweepStateMachineRole,
      // A full sweep of a large fleet runs one account slice at a time and can take many hours; give it a
      // generous ceiling well above any realistic run.
      timeout: Duration.hours(24),
      tracingEnabled: true,
    });

    {
      const childToMod = this.sweepStateMachine.node.findChild('Resource') as sfn.CfnStateMachine;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W11',
              reason:
                'X-Ray tracing requires xray:PutTraceSegments on resource *; scoped as tightly as the API allows.',
            },
          ],
        },
      };
    }

    //---------------------------------------------------------------------
    // Synchronization EventBridge Rule - Weekly scheduled trigger
    //---------------------------------------------------------------------
    const synchronizationWeeklyRule = new Rule(this, 'SynchronizationFindingsLambdaWeeklyRule', {
      ruleName: props.resourceNamePrefix + '-ASR-SynchronizationFindingsLambdaWeeklyRule',
      schedule: Schedule.cron({
        minute: '0',
        hour: '2', // 2 AM UTC
        weekDay: 'SAT', // Every Saturday
      }),
      description: 'Weekly full synchronization of Security Hub findings - always performs complete sync',
    });

    // The weekly schedule starts the sweep state machine, which drives the parallel account fan-out.
    synchronizationWeeklyRule.addTarget(new SfnStateMachine(this.sweepStateMachine, { retryAttempts: 2 }));
  }
}

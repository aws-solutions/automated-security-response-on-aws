// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { StateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { EventbridgeToSqs } from '@aws-solutions-constructs/aws-eventbridge-sqs';
import { EventPattern, IRuleTarget, Rule } from 'aws-cdk-lib/aws-events';
import {
  AccountPrincipal,
  ArnPrincipal,
  CfnRole,
  CompositePrincipal,
  Effect,
  Policy,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { MemberRolesStack } from './member-roles-stack';
import { Construct } from 'constructs';
import setCondition from './cdk-helper/set-condition';
import { Queue } from 'aws-cdk-lib/aws-sqs';

export interface ITriggerProps {
  targetArn: string;
  solutionTMN: string;
  solutionId: string;
}

export class Trigger extends Construct {
  constructor(scope: Construct, id: string, props: ITriggerProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);

    const preProcessorQueue = Queue.fromQueueArn(this, 'preProcessorQueue', props.targetArn) as Queue;

    const eventPattern: EventPattern = {
      source: ['aws.securityhub'],
      detailType: ['Security Hub Findings - Imported', 'Findings Imported V2'], // Security Hub & Security Hub CSPM
      // The below pattern excludes unsupported finding types (e.g., GuardDuty or Macie findings)
      detail: {
        findings: {
          $or: [
            {
              SchemaVersion: ['2018-10-08'], // Security Hub CSPM Control Finding (ASFF Schema)
              ProductArn: [{ prefix: `arn:${stack.partition}:securityhub` }],
            },
            {
              class_name: ['Compliance Finding'], // Security Hub Control Finding (OCSF Schema)
              class_uid: [2003],
              metadata: {
                product: {
                  uid: [{ prefix: `arn:${stack.partition}:securityhub` }],
                },
              },
            },
          ],
        },
      },
    };
    new EventbridgeToSqs(this, 'EventBridgeToSQS', {
      existingQueueObj: preProcessorQueue,
      eventRuleProps: {
        description: `This rule captures finding events from Security Hub & Security Hub CSPM and forwards them to ASR's Pre-processor SQS Queue for further execution`,
        ruleName: `${props.solutionId}_${props.solutionTMN}_AutoTrigger`,
        eventPattern: eventPattern,
        enabled: true,
      },
    });
  }
}

export interface IOneTriggerProps {
  description?: string;
  condition?: cdk.CfnCondition;
  targetArn: string;
  serviceToken: string;
  eventsRole: Role;
  ruleId: string;
  ruleName: string;
  customActionName: string;
  customActionId: string;
  customActionDescription: string;
  prereq: cdk.CfnResource[];
}
export class OneTrigger extends Construct {
  // used in place of Trigger. Sends all finding events for which the
  // ASR custom action is initiated to the Step Function

  constructor(scope: Construct, id: string, props: IOneTriggerProps) {
    super(scope, id);

    // Event to Step Function
    // ----------------------
    // Create CWE rule
    // Create custom action

    let description = `Remediate with ASR`;
    if (props.description) {
      description = props.description;
    }

    const complianceStatusFilter = {
      Status: ['FAILED', 'WARNING'],
    };

    const stateMachine = StateMachine.fromStateMachineArn(this, 'orchestrator', props.targetArn);

    // Note: Id is max 20 characters
    const customAction = new cdk.CustomResource(this, 'Custom Action', {
      serviceToken: props.serviceToken,
      resourceType: 'Custom::ActionTarget',
      properties: {
        Name: props.customActionName,
        Description: props.customActionDescription,
        Id: props.customActionId,
      },
    });
    {
      const cfnCustomAction = customAction.node.defaultChild as cdk.CfnCustomResource;
      for (const prereq of props.prereq) {
        cfnCustomAction.addDependency(prereq);
      }
    }

    // Grant the start execution permission to the Events service
    stateMachine.grantStartExecution(props.eventsRole);

    // Create an event rule to trigger the step function
    const stateMachineTarget: IRuleTarget = {
      bind: () => ({
        id: '',
        arn: props.targetArn,
        role: props.eventsRole,
      }),
    };

    const eventPattern: EventPattern = {
      source: ['aws.securityhub'],
      detailType: ['Security Hub Findings - Custom Action'],
      resources: [customAction.getAttString('Arn')],
      detail: {
        findings: {
          Compliance: complianceStatusFilter,
        },
      },
    };

    const customActionRule = new Rule(this, props.ruleId, {
      description: description,
      enabled: true,
      eventPattern: eventPattern,
      ruleName: props.ruleName,
      targets: [stateMachineTarget],
    });

    if (props.condition) {
      setCondition(customActionRule, props.condition);
      setCondition(customAction, props.condition);
    }
  }
}

export interface RoleProps {
  readonly solutionId: string;
  readonly ssmDocName: string;
  readonly remediationPolicy: Policy;
  readonly remediationRoleName: string;
}

export class SsmRole extends Construct {
  constructor(scope: Construct, id: string, props: RoleProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);
    const roleStack = MemberRolesStack.of(this) as MemberRolesStack;
    const basePolicy = new Policy(this, 'ASR-Member-Base-Policy');
    const roleNameWithNamespace = `${props.remediationRoleName}-${roleStack.getNamespace()}`;

    basePolicy.addStatements(
      new PolicyStatement({
        actions: ['ssm:GetParameters', 'ssm:GetParameter', 'ssm:PutParameter'],
        resources: [`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['iam:PassRole'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${roleNameWithNamespace}`],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['ssm:StartAutomationExecution', 'ssm:GetAutomationExecution', 'ssm:DescribeAutomationStepExecutions'],
        resources: [
          `arn:${stack.partition}:ssm:*:${stack.account}:document/ASR-${props.ssmDocName}`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-definition/*`,
          `arn:${stack.partition}:ssm:*::automation-definition/*`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-execution/*`,
        ],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['sts:AssumeRole'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${roleNameWithNamespace}`],
        effect: Effect.ALLOW,
      }),
    );

    // AssumeRole Policy
    const principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions('sts:AssumeRole');
    principalPolicyStatement.effect = Effect.ALLOW;

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, '');
    const roleprincipal = new ArnPrincipal(
      `arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-ASR-Orchestrator-Member`,
    );

    const principals = new CompositePrincipal(roleprincipal);
    principals.addToPolicy(principalPolicyStatement);

    const serviceprincipal = new ServicePrincipal('ssm.amazonaws.com');
    principals.addPrincipals(serviceprincipal);

    // Multi-account/region automations must be able to assume the remediation role
    const accountPrincipal = new AccountPrincipal(stack.account);
    principals.addPrincipals(accountPrincipal);

    const memberRole = new Role(this, 'MemberAccountRole', {
      assumedBy: principals,
      roleName: `${roleNameWithNamespace}`,
    });

    memberRole.attachInlinePolicy(basePolicy);
    memberRole.attachInlinePolicy(props.remediationPolicy);
    memberRole.node.addDependency(roleStack.getOrchestratorMemberRole());

    const memberRoleResource = memberRole.node.findChild('Resource') as CfnRole;

    memberRoleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W11',
            reason: 'Resource * is required due to the administrative nature of the solution.',
          },
          {
            id: 'W28',
            reason: 'Static names chosen intentionally to provide integration in cross-account permissions',
          },
        ],
      },
    };
  }
}

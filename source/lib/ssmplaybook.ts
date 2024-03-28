// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as events from 'aws-cdk-lib/aws-events';
import {
  Effect,
  PolicyStatement,
  ServicePrincipal,
  Policy,
  Role,
  CfnRole,
  ArnPrincipal,
  CompositePrincipal,
  AccountPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { StateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { IRuleTarget, EventPattern, Rule } from 'aws-cdk-lib/aws-events';
import { MemberRoleStack } from './remediation_runbook-stack';
import { Construct } from 'constructs';

/*
 * @author AWS Solutions Development
 * @description SSM-based remediation trigger
 * @type {trigger}
 */
export interface ITriggerProps {
  description?: string;
  securityStandard: string; // ex. AFSBP
  securityStandardVersion: string;
  generatorId: string; // ex. "arn:aws-cn:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  controlId: string;
  targetArn: string;
}

export class Trigger extends Construct {
  constructor(scope: Construct, id: string, props: ITriggerProps) {
    super(scope, id);
    const illegalChars = /\./g;

    // Event to Step Function
    // ----------------------
    // Create CWE rule
    // Create custom action

    let description = `Remediate ${props.securityStandard} ${props.securityStandardVersion} ${props.controlId}`;
    if (props.description) {
      description = props.description;
    }

    const workflowStatusFilter = {
      Status: ['NEW'],
    };
    const complianceStatusFilter = {
      Status: ['FAILED', 'WARNING'],
    };
    const recordStateFilter: string[] = ['ACTIVE'];

    const stateMachine = sfn.StateMachine.fromStateMachineArn(this, 'orchestrator', props.targetArn);

    // Create an IAM role for Events to start the State Machine
    const eventsRole = new Role(this, 'EventsRuleRole', {
      assumedBy: new ServicePrincipal('events.amazonaws.com'),
    });

    // Grant the start execution permission to the Events service
    stateMachine.grantStartExecution(eventsRole);

    // Create an event rule to trigger the step function
    const stateMachineTarget: events.IRuleTarget = {
      bind: () => ({
        id: '',
        arn: props.targetArn,
        role: eventsRole,
      }),
    };

    const enable_auto_remediation_param = new cdk.CfnParameter(this, 'AutoEnable', {
      description:
        'This will fully enable automated remediation for ' +
        props.securityStandard +
        ' ' +
        props.securityStandardVersion +
        ' ' +
        props.controlId,
      type: 'String',
      allowedValues: ['ENABLED', 'DISABLED'],
      default: 'DISABLED',
    });

    enable_auto_remediation_param.overrideLogicalId(
      `${props.securityStandard}${props.securityStandardVersion}${props.controlId}AutoTrigger`.replace(
        illegalChars,
        '',
      ),
    );

    interface IPattern {
      source: any; // eslint-disable-line @typescript-eslint/no-explicit-any
      detailType: any; // eslint-disable-line @typescript-eslint/no-explicit-any
      detail: any; // eslint-disable-line @typescript-eslint/no-explicit-any
    }
    const eventPattern: IPattern = {
      source: ['aws.securityhub'],
      detailType: ['Security Hub Findings - Imported'],
      detail: {
        findings: {
          // GeneratorId includes both standard and control/rule ID
          GeneratorId: [props.generatorId],
          Workflow: workflowStatusFilter,
          Compliance: complianceStatusFilter,
          RecordState: recordStateFilter,
        },
      },
    };

    const triggerPattern: events.EventPattern = eventPattern;

    // Adding an automated even rule for the playbook
    const eventRule_auto = new events.Rule(this, 'AutoEventRule', {
      description: description + ' automatic remediation trigger event rule.',
      ruleName: `${props.securityStandard}_${props.securityStandardVersion}_${props.controlId}_AutoTrigger`,
      targets: [stateMachineTarget],
      eventPattern: triggerPattern,
    });

    const cfnEventRule_auto = eventRule_auto.node.defaultChild as events.CfnRule;
    cfnEventRule_auto.addPropertyOverride('State', enable_auto_remediation_param.valueAsString);
  }
}

export interface IOneTriggerProps {
  description?: string;
  targetArn: string;
  serviceToken: string;
  prereq: cdk.CfnResource[];
}
export class OneTrigger extends Construct {
  // used in place of Trigger. Sends all finding events for which the
  // SHARR custom action is initiated to the Step Function

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
        Name: 'Remediate with ASR',
        Description: 'Submit the finding to AWS Security Hub Automated Response and Remediation',
        Id: 'ASRRemediation',
      },
    });
    {
      const child = customAction.node.defaultChild as cdk.CfnCustomResource;
      for (const prereq of props.prereq) {
        child.addDependency(prereq);
      }
    }

    // Create an IAM role for Events to start the State Machine
    const eventsRole = new Role(this, 'EventsRuleRole', {
      assumedBy: new ServicePrincipal('events.amazonaws.com'),
    });

    // Grant the start execution permission to the Events service
    stateMachine.grantStartExecution(eventsRole);

    // Create an event rule to trigger the step function
    const stateMachineTarget: IRuleTarget = {
      bind: () => ({
        id: '',
        arn: props.targetArn,
        role: eventsRole,
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

    new Rule(this, 'Remediate Custom Action', {
      description: description,
      enabled: true,
      eventPattern: eventPattern,
      ruleName: `Remediate_with_SHARR_CustomAction`,
      targets: [stateMachineTarget],
    });
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
    const roleStack = MemberRoleStack.of(this) as MemberRoleStack;
    const basePolicy = new Policy(this, 'SHARR-Member-Base-Policy');

    basePolicy.addStatements(
      new PolicyStatement({
        actions: ['ssm:GetParameters', 'ssm:GetParameter', 'ssm:PutParameter'],
        resources: [`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['iam:PassRole'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${props.remediationRoleName}`],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['ssm:StartAutomationExecution', 'ssm:GetAutomationExecution', 'ssm:DescribeAutomationStepExecutions'],
        resources: [
          `arn:${stack.partition}:ssm:*:${stack.account}:document/Solutions/SHARR-${props.remediationRoleName}`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-definition/*`,
          `arn:${stack.partition}:ssm:*::automation-definition/*`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-execution/*`,
        ],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['sts:AssumeRole'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${props.remediationRoleName}`],
        effect: Effect.ALLOW,
      }),
    );

    // AssumeRole Policy
    const principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions('sts:AssumeRole');
    principalPolicyStatement.effect = Effect.ALLOW;

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, '');
    const roleprincipal = new ArnPrincipal(
      `arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-SHARR-Orchestrator-Member`,
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
      roleName: props.remediationRoleName,
    });

    memberRole.attachInlinePolicy(basePolicy);
    memberRole.attachInlinePolicy(props.remediationPolicy);
    memberRole.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
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

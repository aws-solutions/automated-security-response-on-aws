// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  CfnCondition,
  CfnParameter,
  CfnRule,
  CustomResource,
  Duration,
  Fn,
  ICfnRuleConditionExpression,
  Stack,
} from 'aws-cdk-lib';
import { PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Clock, getClock } from '@asr/data-models';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './add-cfn-guard-suppression';
import { getLambdaCode } from './lambda-code-manifest';
import { createLogGroup } from './log-group';

export interface PlaybookSelectionValidatorProps {
  readonly solutionTradeMarkName: string;
  readonly solutionVersion: string;
  readonly runtimePython: lambda.Runtime;
  readonly solutionsBucket: IBucket;
  readonly securityControlPlaybookParameter: CfnParameter;
  readonly standardPlaybookParameters: CfnParameter[];
  /** When false, a Region without Security Hub deploys with a warning instead of failing. */
  readonly isSecurityHubRequired: boolean;
  readonly clock?: Clock;
}

/**
 * A CloudFormation Rule rejects an empty playbook selection, and a custom resource rejects a selection that
 * cannot remediate control findings under the account's Security Hub consolidated control findings setting.
 */
export class PlaybookSelectionValidator extends Construct {
  private readonly validation: CustomResource;

  constructor(scope: Construct, id: string, props: PlaybookSelectionValidatorProps) {
    super(scope, id);
    const stack = Stack.of(this);

    PlaybookSelectionValidator.createSelectionRule(this, props);
    const isStandardPlaybookSelected = new CfnCondition(this, 'StandardPlaybookSelected', {
      expression: Fn.conditionOr(...props.standardPlaybookParameters.map(PlaybookSelectionValidator.isSelected)),
    });

    const logGroup = createLogGroup(this, 'LogGroup');
    const role = new Role(this, 'Role', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Reads the Security Hub settings to validate the ASR playbook selection',
      inlinePolicies: {
        PlaybookSelectionValidatorPolicy: new PolicyDocument({
          statements: [
            new PolicyStatement({
              actions: ['securityhub:DescribeHub'],
              resources: [`arn:${stack.partition}:securityhub:${stack.region}:${stack.account}:hub/default`],
            }),
            new PolicyStatement({ actions: ['cloudformation:DescribeStacks'], resources: [stack.stackId] }),
            new PolicyStatement({
              actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              resources: [logGroup.logGroupArn],
            }),
          ],
        }),
      },
    });
    addCfnGuardSuppression(role, 'IAM_NO_INLINE_POLICY_CHECK');

    const validatorFunction = new lambda.Function(this, 'Function', {
      code: getLambdaCode(
        props.solutionsBucket,
        props.solutionTradeMarkName,
        props.solutionVersion,
        'playbook_selection_validator.zip',
      ),
      handler: 'playbook_selection_validator.lambda_handler',
      runtime: props.runtimePython,
      description: 'ASR - Validates the playbook selection against the Security Hub settings',
      environment: { LOG_LEVEL: 'INFO' },
      timeout: Duration.minutes(5),
      role,
      logGroup,
    });
    addCfnGuardSuppression(validatorFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(validatorFunction, 'LAMBDA_CONCURRENCY_CHECK');

    this.validation = new CustomResource(this, 'Validation', {
      resourceType: 'Custom::PlaybookSelectionValidator',
      serviceToken: validatorFunction.functionArn,
      properties: {
        SecurityControlPlaybookSelected: props.securityControlPlaybookParameter.valueAsString,
        StandardPlaybookSelected: Fn.conditionIf(isStandardPlaybookSelected.logicalId, 'yes', 'no'),
        SecurityHubRequired: props.isSecurityHubRequired ? 'yes' : 'no',
        // Changes at every synthesis, so CloudFormation sends Update and re-validates on every template upgrade.
        Timestamp: (props.clock ?? getClock()).now().getTime().toString(),
      },
    });
  }

  addDependent(nestedStack: Stack): void {
    const nestedStackResource = nestedStack.nestedStackResource;
    if (!nestedStackResource) {
      throw new Error(`${nestedStack.node.path} is not a nested stack`);
    }
    nestedStackResource.node.addDependency(this.validation);
  }

  private static isSelected(parameter: CfnParameter): ICfnRuleConditionExpression {
    return Fn.conditionEquals(parameter.valueAsString, 'yes');
  }

  private static createSelectionRule(scope: Construct, props: PlaybookSelectionValidatorProps): void {
    const isSecurityControlSelected = PlaybookSelectionValidator.isSelected(props.securityControlPlaybookParameter);
    const isAnyStandardSelected = Fn.conditionOr(
      ...props.standardPlaybookParameters.map(PlaybookSelectionValidator.isSelected),
    );

    new CfnRule(scope, 'SelectionRule', {
      assertions: [
        {
          assert: Fn.conditionOr(isSecurityControlSelected, isAnyStandardSelected),
          assertDescription:
            'Select at least one playbook: the Security Control (SC) playbook when consolidated control findings ' +
            'are turned on in Security Hub, or the security standard playbooks when they are turned off.',
        },
      ],
    });
  }
}

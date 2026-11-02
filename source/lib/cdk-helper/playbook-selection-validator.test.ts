// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, CfnParameter, DefaultStackSynthesizer, NestedStack, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Clock } from '@asr/data-models';
import { PlaybookSelectionValidator } from './playbook-selection-validator';

const SECURITY_CONTROL_PARAMETER = 'LoadSCAdminStack';
const STANDARD_PARAMETERS = ['LoadAFSBPAdminStack', 'LoadCIS120AdminStack', 'LoadNIST80053AdminStack'];
const SYNTHESIS_TIME = new Date('2025-01-01T00:00:00.000Z');
const fixedClock: Clock = { now: () => SYNTHESIS_TIME };

type PlaybookSelection = Record<string, 'yes' | 'no'>;

interface RuleExpression {
  readonly 'Fn::And'?: RuleExpression[];
  readonly 'Fn::Or'?: RuleExpression[];
  readonly 'Fn::Not'?: [RuleExpression];
  readonly 'Fn::Equals'?: [{ Ref: string }, string];
  readonly Condition?: string;
}

interface RuleAssertion {
  readonly Assert: RuleExpression;
  readonly AssertDescription: string;
}

interface InlinePolicy {
  readonly PolicyDocument: { Statement: unknown[] };
}

interface ValidatorTestStack {
  stack: Stack;
  validator: PlaybookSelectionValidator;
}

function createValidatorStack(isSecurityHubRequired = true): ValidatorTestStack {
  const stack = new Stack(new App(), 'TestStack', {
    env: { account: '111111111111', region: 'us-east-1' },
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });
  const createParameter = (name: string): CfnParameter => {
    const parameter = new CfnParameter(stack, name, { type: 'String', allowedValues: ['yes', 'no'] });
    parameter.overrideLogicalId(name);
    return parameter;
  };
  const validator = new PlaybookSelectionValidator(stack, 'PlaybookSelectionValidator', {
    solutionTradeMarkName: 'automated-security-response-on-aws',
    solutionVersion: 'v1.0.0',
    runtimePython: Runtime.PYTHON_3_11,
    solutionsBucket: Bucket.fromBucketName(stack, 'SolutionsBucket', 'solutions-us-east-1'),
    securityControlPlaybookParameter: createParameter(SECURITY_CONTROL_PARAMETER),
    standardPlaybookParameters: STANDARD_PARAMETERS.map(createParameter),
    isSecurityHubRequired,
    clock: fixedClock,
  });
  return { stack, validator };
}

// Evaluates the subset of rule intrinsics the validator emits, so the test checks what
// CloudFormation would decide rather than the shape of the expression.
function evaluateRuleExpression(
  expression: RuleExpression,
  selection: PlaybookSelection,
  conditions: Record<string, RuleExpression> = {},
): boolean {
  const { 'Fn::And': and, 'Fn::Or': or, 'Fn::Not': not, 'Fn::Equals': equals, Condition: condition } = expression;
  const evaluate = (operand: RuleExpression): boolean => evaluateRuleExpression(operand, selection, conditions);
  if (and) return and.every(evaluate);
  if (or) return or.some(evaluate);
  if (not) return !evaluate(not[0]);
  if (equals) return selection[equals[0].Ref] === equals[1];
  if (condition) return evaluate(conditions[condition]);
  throw new Error(`Unsupported rule expression: ${JSON.stringify(expression)}`);
}

function getRuleAssertions(template: Template): RuleAssertion[] {
  const rules: { Assertions: RuleAssertion[] }[] = Object.values(template.toJSON().Rules ?? {});
  expect(rules).toHaveLength(1);
  return rules[0].Assertions;
}

function getRejectionDescriptions(template: Template, selection: PlaybookSelection): string[] {
  return getRuleAssertions(template)
    .filter((assertion) => !evaluateRuleExpression(assertion.Assert, selection))
    .map((assertion) => assertion.AssertDescription);
}

function allSelections(): PlaybookSelection[] {
  const parameters = [SECURITY_CONTROL_PARAMETER, ...STANDARD_PARAMETERS];
  return Array.from({ length: 2 ** parameters.length }, (_, combination) =>
    Object.fromEntries(
      parameters.map((parameter, index): [string, 'yes' | 'no'] => [
        parameter,
        (combination >> index) & 1 ? 'yes' : 'no',
      ]),
    ),
  );
}

describe('PlaybookSelectionValidator', () => {
  let template: Template;
  let validatorStack: ValidatorTestStack;

  beforeAll(() => {
    validatorStack = createValidatorStack();
    template = Template.fromStack(validatorStack.stack);
  });

  it('rule accepts every selection that includes at least one playbook, including SC with standard playbooks', () => {
    // ARRANGE
    const isValidSelection = (selection: PlaybookSelection): boolean =>
      Object.values(selection).some((value) => value === 'yes');

    // ACT
    const outcomes = allSelections().map((selection) => ({
      selection,
      isAccepted: getRejectionDescriptions(template, selection).length === 0,
    }));

    // ASSERT
    outcomes.forEach(({ selection, isAccepted }) => {
      expect({ selection, isAccepted }).toEqual({ selection, isAccepted: isValidSelection(selection) });
    });
  });

  it('rule explains why an empty selection is rejected', () => {
    // ARRANGE
    const nothingSelected: PlaybookSelection = Object.fromEntries(
      [SECURITY_CONTROL_PARAMETER, ...STANDARD_PARAMETERS].map((parameter) => [parameter, 'no']),
    );

    // ACT
    const emptyReasons = getRejectionDescriptions(template, nothingSelected);

    // ASSERT
    expect(emptyReasons).toEqual([expect.stringContaining('Select at least one playbook')]);
  });

  it('function outlives the worst-case retries of both API calls, so CloudFormation always gets an answer', () => {
    // ASSERT
    const functions = Object.values(template.findResources('AWS::Lambda::Function'));
    expect(functions).toHaveLength(1);
    const timeoutSeconds: number = functions[0].Properties.Timeout;
    expect(timeoutSeconds).toBeGreaterThanOrEqual(120);
  });

  it('custom resource re-runs on every template upgrade and receives the SC selection and whether Security Hub is required', () => {
    // ARRANGE
    const securityHubOptionalTemplate = Template.fromStack(createValidatorStack(false).stack);

    // ASSERT
    template.hasResourceProperties('Custom::PlaybookSelectionValidator', {
      SecurityControlPlaybookSelected: { Ref: SECURITY_CONTROL_PARAMETER },
      SecurityHubRequired: 'yes',
      Timestamp: SYNTHESIS_TIME.getTime().toString(),
    });
    securityHubOptionalTemplate.hasResourceProperties('Custom::PlaybookSelectionValidator', {
      SecurityHubRequired: 'no',
    });
  });

  it('custom resource reports yes for standard playbooks exactly when any standard playbook is selected', () => {
    // ARRANGE
    const templateJson = template.toJSON();
    const conditions: Record<string, RuleExpression> = templateJson.Conditions;
    const [validation] = Object.values(template.findResources('Custom::PlaybookSelectionValidator'));
    const [conditionName, valueWhenTrue, valueWhenFalse]: [string, string, string] =
      validation.Properties.StandardPlaybookSelected['Fn::If'];

    // ACT
    const outcomes = allSelections().map((selection) => ({
      selection,
      reported: evaluateRuleExpression({ Condition: conditionName }, selection, conditions)
        ? valueWhenTrue
        : valueWhenFalse,
    }));

    // ASSERT
    outcomes.forEach(({ selection, reported }) => {
      const isAnyStandardSelected = STANDARD_PARAMETERS.some((parameter) => selection[parameter] === 'yes');
      expect({ selection, reported }).toEqual({ selection, reported: isAnyStandardSelected ? 'yes' : 'no' });
    });
  });

  it('role grants only DescribeHub, DescribeStacks on its own stack, and writes to its own log group', () => {
    // ASSERT
    const logGroupLogicalIds = Object.keys(template.findResources('AWS::Logs::LogGroup'));
    expect(logGroupLogicalIds).toHaveLength(1);
    const roles = Object.values(template.findResources('AWS::IAM::Role'));
    expect(roles).toHaveLength(1);
    const policies: InlinePolicy[] = roles[0].Properties.Policies;
    const statements = policies.flatMap((policy) => policy.PolicyDocument.Statement);
    expect(statements).toEqual([
      {
        Action: 'securityhub:DescribeHub',
        Effect: 'Allow',
        Resource: {
          'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':securityhub:us-east-1:111111111111:hub/default']],
        },
      },
      { Action: 'cloudformation:DescribeStacks', Effect: 'Allow', Resource: { Ref: 'AWS::StackId' } },
      {
        Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        Effect: 'Allow',
        Resource: { 'Fn::GetAtt': [logGroupLogicalIds[0], 'Arn'] },
      },
    ]);
    expect(template.findResources('AWS::IAM::Policy')).toEqual({});
  });

  it('makes a dependent nested stack wait for the validation', () => {
    // ARRANGE
    const { stack, validator } = createValidatorStack();
    const nestedStack = new NestedStack(stack, 'PlaybookNestedStack');

    // ACT
    validator.addDependent(nestedStack);

    // ASSERT
    const validatorLogicalIds = Object.keys(
      Template.fromStack(stack).findResources('Custom::PlaybookSelectionValidator'),
    );
    Template.fromStack(stack).hasResource('AWS::CloudFormation::Stack', {
      DependsOn: Match.arrayWith(validatorLogicalIds),
    });
  });

  it('refuses a stack that is not nested, because it has no resource to gate', () => {
    // ARRANGE
    const { validator } = createValidatorStack();

    // ACT / ASSERT
    expect(() => validator.addDependent(new Stack())).toThrow('is not a nested stack');
  });
});

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  App,
  Stack,
  CustomResource,
  Duration,
  CfnParameter,
  StackProps,
} from "aws-cdk-lib";
import { RemediationResourcesStack } from "./nested-stacks/remediation-resources-stack";
import { Provider } from "aws-cdk-lib/custom-resources";
import { Rule, Schedule } from "aws-cdk-lib/aws-events";
import { LambdaFunction } from "aws-cdk-lib/aws-events-targets";
import { Code, Function, Runtime } from "aws-cdk-lib/aws-lambda";
import {
  Policy,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from "aws-cdk-lib/aws-iam";

import { readFileSync } from "fs";

// Security Hub Controls (by playbook) whose resources have been implemented in this stack.
// When adding a new control, add the control ID as it exists in each implemented security standard/playbook. You must also update enable_remediation_rules.py
// Note: not all controls exist in every security standard
const IMPLEMENTED_CONTROLS: Record<string, string[]> = JSON.parse(
  readFileSync("../common/controls.json", "utf-8"),
);

export class TestStack extends Stack {
  constructor(scope: App, id: string, props: StackProps) {
    super(scope, id, props);
    const stack = Stack.of(this);

    const securityStandardParam = new CfnParameter(this, "SecurityStandard", {
      description: "ASR playbook which you have deployed.",
      type: "String",
      allowedValues: ["SC", "AFSBP", "CIS", "NIST", "PCI"],
      default: "SC",
    });

    const securityStandardVersion = new CfnParameter(
      this,
      "SecurityStandardVersion",
      {
        description:
          "The version of the playbook which you have deployed. You can find the standard version in the following file within the solution repository: source/playbooks/PLAYBOOK/bin/PLAYBOOK.ts - For the SC playbook, enter '2.0.0'",
        type: "String",
        default: "2.0.0",
      },
    );

    const remediationFrequencyParam = new CfnParameter(
      this,
      "RemediationFrequency",
      {
        description:
          "Choose how frequently (in minutes) you wish to trigger remediations. This will determine how often the test resources created by this stack are reset to their original state. Default is daily.",
        type: "Number",
        default: "1440",
      },
    );

    const remediationResourcesStack = new RemediationResourcesStack(
      this,
      "RemediationResourcesStack",
      {},
    );

    // Give the custom resource permission to enable all possible rules, since we cannot be more specific at synth-time.
    const policyStatements: PolicyStatement[] = [];
    Object.values(IMPLEMENTED_CONTROLS).forEach((controlIds) => {
      controlIds.forEach((controlId) => {
        policyStatements.push(
          new PolicyStatement({
            actions: ["events:EnableRule"],
            resources: [
              `arn:${stack.partition}:events:${stack.region}:${stack.account}:rule/${securityStandardParam.valueAsString}_${securityStandardVersion.valueAsString}_${controlId}_AutoTrigger`,
            ],
          }),
        );
      });
    });

    const enableRemediationRulesPolicy = new Policy(
      this,
      `EnableRemediationRulesPolicy`,
      {
        statements: [
          ...policyStatements,
          new PolicyStatement({
            actions: [
              "logs:CreateLogGroup",
              "logs:CreateLogStream",
              "logs:PutLogEvents",
            ],
            resources: ["*"],
          }),
        ],
      },
    );

    const enableRemediationRulesRole = new Role(
      this,
      "EnableRemediationRulesRole",
      {
        assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
        description:
          "Role created by the ASR TestStack with permissions for the EnableRemediationRules custom resource.",
      },
    );
    enableRemediationRulesRole.attachInlinePolicy(enableRemediationRulesPolicy);

    const enableRemediationRules = new Function(
      this,
      "EnableRemediationRules",
      {
        runtime: Runtime.PYTHON_3_11,
        handler: "enable_remediation_rules.lambda_handler",
        code: Code.fromAsset("../lambda/enable_remediation_rules.zip"),
        memorySize: 256,
        timeout: Duration.seconds(30),
        role: enableRemediationRulesRole,
      },
    );

    const provider = new Provider(this, "EnableRulesProvider", {
      onEventHandler: enableRemediationRules,
    });

    new CustomResource(this, "EnableRulesCustomResource", {
      resourceType: "Custom::EnableRemediationRules",
      serviceToken: provider.serviceToken,
      properties: {
        SecurityStandard: securityStandardParam.valueAsString,
        SecurityStandardVersion: securityStandardVersion.valueAsString,
      },
    });

    const resetResourcesPolicy = new Policy(this, "ResetResourcesPolicy", {
      statements: [
        new PolicyStatement({
          actions: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ],
          resources: ["*"],
        }),
        new PolicyStatement({
          actions: ["s3:PutBucketLogging"],
          resources: [remediationResourcesStack.getS3Bucket().bucketArn],
        }),
        new PolicyStatement({
          actions: ["kms:DisableKeyRotation"],
          resources: [remediationResourcesStack.getKmsKey().keyArn],
        }),
        new PolicyStatement({
          actions: ["secretsmanager:CancelRotateSecret"],
          resources: [remediationResourcesStack.getSecret().secretArn],
        }),
        new PolicyStatement({
          actions: ["sqs:SetQueueAttributes"],
          resources: [remediationResourcesStack.getSqsQueue().queueArn],
        }),
      ],
    });

    const resetResourcesRole = new Role(this, "ResetResourcesRole", {
      assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
      description:
        "Role created by the ASR TestStack with permissions for the ResetRemediationResources lambda function.",
    });
    resetResourcesRole.attachInlinePolicy(resetResourcesPolicy);

    const resetResourcesFunction = new Function(
      this,
      "ResetResourcesFunction",
      {
        runtime: Runtime.PYTHON_3_11,
        description:
          "Function created by the ASR TestStack to reset all remediation resources created by the props.RemediationResourcesStack to their original state.",
        handler: "reset_remediation_resources.lambda_handler",
        code: Code.fromAsset("../lambda/reset_remediation_resources.zip"),
        memorySize: 512,
        timeout: Duration.seconds(15),
        role: resetResourcesRole,
        environment: {
          BucketName: remediationResourcesStack.getS3Bucket().bucketName,
          KMSKeyId: remediationResourcesStack.getKmsKey().keyId,
          SecretId: remediationResourcesStack.getSecret().secretName,
          QueueURL: remediationResourcesStack.getSqsQueue().queueUrl,
        },
      },
    );

    const resetResourcesSchedule = new Rule(this, "ResetResourcesSchedule", {
      schedule: Schedule.rate(
        Duration.minutes(remediationFrequencyParam.valueAsNumber),
      ),
    });

    resetResourcesSchedule.addTarget(
      new LambdaFunction(resetResourcesFunction, {
        retryAttempts: 2,
      }),
    );
  }
}

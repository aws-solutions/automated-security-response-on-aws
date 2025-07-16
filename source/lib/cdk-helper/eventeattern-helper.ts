// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { EventPattern } from 'aws-cdk-lib/aws-events';

interface EventPatternProps {
  generatorId: string;
  isAllInclude: cdk.CfnCondition;
  isAllExclude: cdk.CfnCondition;
  isInclude: cdk.CfnCondition;
  targetAccountIDs: cdk.CfnParameter;
}

export class EventPatternHelper {
  //GeneratorId | Length Constraints: Maximum length of 512. | https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFinding.html
  private static readonly GeneratorIdLength: number = 512;
  //EventPattern | Length Constraints: Maximum length of 4096. | https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html
  private static readonly EventPatternLength: number = 4096;
  private static readonly PatterCharsBufferLength: number = 20;

  public static readonly WORKFLOW_STATUS: { Status: string[] } = {
    Status: ['NEW'],
  };

  public static readonly COMPLIANCE_STATUS: { Status: string[] } = {
    Status: ['FAILED', 'WARNING'],
  };

  public static readonly RECORD_STATE: string[] = ['ACTIVE'];

  private props: EventPatternProps;

  constructor(props: EventPatternProps) {
    this.props = props;
  }

  public static getPatternLength(pattern: any): number {
    return JSON.stringify(pattern).length;
  }

  public static getPatternMaxLength(): number {
    const baseLength = this.getPatternLength(this.getBasePattern());
    return (
      EventPatternHelper.EventPatternLength -
      (baseLength + EventPatternHelper.GeneratorIdLength + EventPatternHelper.PatterCharsBufferLength)
    );
  }

  public createEventPattern(): EventPattern {
    const basePattern = EventPatternHelper.getBasePattern();
    const accountPattern = this.getAccountPattern();
    const generatorPattern = this.getGeneratorIdPattern();

    return {
      ...basePattern,
      detail: {
        findings: {
          ...basePattern.detail.findings,
          ...generatorPattern,
          ...accountPattern,
        },
      },
    };
  }

  private static getBasePattern(): any {
    return {
      source: ['aws.securityhub'],
      detailType: ['Security Hub Findings - Imported'],
      detail: {
        findings: {
          Workflow: EventPatternHelper.WORKFLOW_STATUS,
          Compliance: EventPatternHelper.COMPLIANCE_STATUS,
          RecordState: EventPatternHelper.RECORD_STATE,
        },
      },
    };
  }

  private getGeneratorIdPattern(): any {
    return {
      GeneratorId: [this.props.generatorId],
    };
  }

  private getAccountPattern(): any {
    return {
      AwsAccountId: cdk.Fn.conditionIf(
        this.props.isAllInclude.logicalId,
        cdk.Aws.NO_VALUE,
        cdk.Fn.conditionIf(
          this.props.isAllExclude.logicalId,
          [{ exists: false }],
          cdk.Fn.conditionIf(
            this.props.isInclude.logicalId,
            cdk.Fn.split(',', this.props.targetAccountIDs.valueAsString),
            [{ 'anything-but': cdk.Fn.split(',', this.props.targetAccountIDs.valueAsString) }],
          ),
        ),
      ),
    };
  }
}

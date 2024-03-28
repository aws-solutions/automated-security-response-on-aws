// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  ExecuteScriptStep,
  HardCodedString,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAutomaticVersionUpgradeOnRedshiftClusterDocument(scope, id, { ...props, controlId: 'Redshift.6' });
}

export class EnableAutomaticVersionUpgradeOnRedshiftClusterDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Redshift.6',
      remediationName: 'EnableAutomaticVersionUpgradeOnRedshiftCluster',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ClusterIdentifier',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):redshift:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:cluster:(?!.*--)([a-z][a-z0-9-]{0,62})(?<!-)$`,
      updateDescription: HardCodedString.of('Enabled automatic version upgrade on Redshift cluster'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'AllowVersionUpgradeSerialized',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.aws_config_rule.InputParameters',
    });

    return outputs;
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      new ExecuteScriptStep(this, 'ExtractConfigRuleParameters', {
        language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'event_handler'),
        code: ScriptCode.fromFile(fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'deserialize_json.py'))),
        outputs: [
          {
            name: 'AllowVersionUpgrade',
            outputType: DataTypeEnum.STRING,
            selector: '$.Payload.allowVersionUpgrade',
          },
        ],
        inputPayload: { SerializedJson: StringVariable.of('ParseInput.AllowVersionUpgradeSerialized') },
      }),
    ];
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.AllowVersionUpgrade = StringVariable.of('ExtractConfigRuleParameters.AllowVersionUpgrade');

    return params;
  }
}

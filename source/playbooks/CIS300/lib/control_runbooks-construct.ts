// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CfnCondition, CfnParameter, Fn } from 'aws-cdk-lib';
import * as cis_300_3_1 from '../ssmdocs/CIS300_3.1';
import * as cis_300_1_8 from '../ssmdocs/CIS300_1.8';
import * as cis_300_1_12 from '../ssmdocs/CIS300_1.12';
import * as cis_300_1_14 from '../ssmdocs/CIS300_1.14';
import * as cis_300_1_17 from '../ssmdocs/CIS300_1.17';
import * as cis_300_2_1_1 from '../ssmdocs/CIS300_2.1.1';
import * as cis_300_2_1_4 from '../ssmdocs/CIS300_2.1.4';
import * as cis_300_2_2_1 from '../ssmdocs/CIS300_2.2.1';
import * as cis_300_2_3_2 from '../ssmdocs/CIS300_2.3.2';
import * as cis_300_2_3_3 from '../ssmdocs/CIS300_2.3.3';
import * as cis_300_3_2 from '../ssmdocs/CIS300_3.2';
import * as cis_300_3_3 from '../ssmdocs/CIS300_3.3';
import * as cis_300_3_4 from '../ssmdocs/CIS300_3.4';
import * as cis_300_3_5 from '../ssmdocs/CIS300_3.5';
import * as cis_300_3_6 from '../ssmdocs/CIS300_3.6';
import * as cis_300_3_7 from '../ssmdocs/CIS300_3.7';
import * as cis_300_5_4 from '../ssmdocs/CIS300_5.4';
import * as cis_300_5_6 from '../ssmdocs/CIS300_5.6';

import { IControl } from '../../../lib/sharrplaybook-construct';

export interface ControlRunbooksProps {
  standardShortName: string;
  standardLongName: string;
  standardVersion: string;
  runtimePython: Runtime;
  solutionId: string;
  solutionAcronym: string;
  solutionVersion: string;
  remediations: IControl[];
  namespace: string;
}

const controlRunbooksRecord: Record<string, any> = {
  '3.1': cis_300_3_1.createControlRunbook,
  '3.5': cis_300_3_5.createControlRunbook,
  '3.2': cis_300_3_2.createControlRunbook,
  '3.4': cis_300_3_4.createControlRunbook,
  '3.3': cis_300_3_3.createControlRunbook,
  '5.4': cis_300_5_4.createControlRunbook,
  '3.7': cis_300_3_7.createControlRunbook,
  '2.2.1': cis_300_2_2_1.createControlRunbook,
  '5.6': cis_300_5_6.createControlRunbook,
  '1.14': cis_300_1_14.createControlRunbook,
  '1.8': cis_300_1_8.createControlRunbook,
  '1.17': cis_300_1_17.createControlRunbook,
  '1.12': cis_300_1_12.createControlRunbook,
  '3.6': cis_300_3_6.createControlRunbook,
  '2.3.3': cis_300_2_3_3.createControlRunbook,
  '2.3.2': cis_300_2_3_2.createControlRunbook,
  '2.1.4': cis_300_2_1_4.createControlRunbook,
  '2.1.1': cis_300_2_1_1.createControlRunbook,
};

export class ControlRunbooks extends Construct {
  protected readonly standardLongName: string;
  protected readonly standardVersion: string;
  protected controls: Set<string> = new Set<string>();

  constructor(scope: Construct, id: string, props: ControlRunbooksProps) {
    super(scope, id);

    this.standardLongName = props.standardLongName;
    this.standardVersion = props.standardVersion;

    for (const remediation of props.remediations) {
      const controlId = remediation.control;

      if (remediation.executes) continue; // Skip remediations that map to other controls
      this.add(controlRunbooksRecord[controlId](this, controlId, props));
    }
  }

  protected add(document: ControlRunbookDocument) {
    const controlId = document.getControlId();
    const enableParamDescription = this.getEnableParamDescription(controlId);
    const enableParamValueAvailable = 'Available';
    const enableParam = new CfnParameter(this, `Enable ${controlId}`, {
      type: 'String',
      description: enableParamDescription,
      default: enableParamValueAvailable,
      allowedValues: [enableParamValueAvailable, 'NOT Available'],
    });

    document.cfnDocument.cfnOptions.condition = new CfnCondition(this, `Enable ${controlId} Condition`, {
      expression: Fn.conditionEquals(enableParam, enableParamValueAvailable),
    });

    this.controls.add(document.getControlId());
  }

  protected getEnableParamDescription(controlId: string) {
    return (
      `Enable/disable availability of remediation for ${this.standardLongName} version ` +
      `${this.standardVersion} Control ${controlId} in Security Hub Console Custom Actions. If ` +
      'NOT Available the remediation cannot be triggered from the Security Hub console in the ' +
      'Security Hub Admin account.'
    );
  }

  public has(controlId: string): boolean {
    return this.controls.has(controlId);
  }
}

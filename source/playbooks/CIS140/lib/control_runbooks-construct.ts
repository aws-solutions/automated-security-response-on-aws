// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CfnCondition, CfnParameter, Fn } from 'aws-cdk-lib';

import * as cis_140_1_8 from '../ssmdocs/CIS140_1.8';
import * as cis_140_1_12 from '../ssmdocs/CIS140_1.12';
import * as cis_140_1_14 from '../ssmdocs/CIS140_1.14';
import * as cis_140_1_17 from '../ssmdocs/CIS140_1.17';
import * as cis_140_2_1_1 from '../ssmdocs/CIS140_2.1.1';
import * as cis_140_2_1_2 from '../ssmdocs/CIS140_2.1.2';
import * as cis_140_2_1_5_1 from '../ssmdocs/CIS140_2.1.5.1';
import * as cis_140_2_1_5_2 from '../ssmdocs/CIS140_2.1.5.2';
import * as cis_140_2_2_1 from '../ssmdocs/CIS140_2.2.1';
import * as cis_140_3_1 from '../ssmdocs/CIS140_3.1';
import * as cis_140_3_2 from '../ssmdocs/CIS140_3.2';
import * as cis_140_3_3 from '../ssmdocs/CIS140_3.3';
import * as cis_140_3_4 from '../ssmdocs/CIS140_3.4';
import * as cis_140_3_5 from '../ssmdocs/CIS140_3.5';
import * as cis_140_3_6 from '../ssmdocs/CIS140_3.6';
import * as cis_140_3_7 from '../ssmdocs/CIS140_3.7';
import * as cis_140_3_8 from '../ssmdocs/CIS140_3.8';
import * as cis_140_3_9 from '../ssmdocs/CIS140_3.9';
import * as cis_140_4_1 from '../ssmdocs/CIS140_4.1';
import * as cis_140_5_3 from '../ssmdocs/CIS140_5.3';
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
  '1.8': cis_140_1_8.createControlRunbook,
  '1.12': cis_140_1_12.createControlRunbook,
  '1.14': cis_140_1_14.createControlRunbook,
  '1.17': cis_140_1_17.createControlRunbook,
  '2.1.1': cis_140_2_1_1.createControlRunbook,
  '2.1.2': cis_140_2_1_2.createControlRunbook,
  '2.1.5.1': cis_140_2_1_5_1.createControlRunbook, //NOSONAR This is not an IP Address.
  '2.1.5.2': cis_140_2_1_5_2.createControlRunbook, //NOSONAR This is not an IP Address.
  '2.2.1': cis_140_2_2_1.createControlRunbook,
  '3.1': cis_140_3_1.createControlRunbook,
  '3.2': cis_140_3_2.createControlRunbook,
  '3.3': cis_140_3_3.createControlRunbook,
  '3.4': cis_140_3_4.createControlRunbook,
  '3.5': cis_140_3_5.createControlRunbook,
  '3.6': cis_140_3_6.createControlRunbook,
  '3.7': cis_140_3_7.createControlRunbook,
  '3.8': cis_140_3_8.createControlRunbook,
  '3.9': cis_140_3_9.createControlRunbook,
  '4.1': cis_140_4_1.createControlRunbook,
  '5.3': cis_140_5_3.createControlRunbook,
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

    const installSsmDoc = new CfnCondition(this, `Enable ${controlId} Condition`, {
      expression: Fn.conditionEquals(enableParam, enableParamValueAvailable),
    });

    document.cfnDocument.cfnOptions.condition = installSsmDoc;

    this.controls.add(document.getControlId());
  }

  protected getEnableParamDescription(controlId: string) {
    // eslint-disable-next-line prettier/prettier
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

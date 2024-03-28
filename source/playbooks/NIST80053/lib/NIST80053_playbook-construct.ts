// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack, App, StackProps, CfnParameter, Aspects } from 'aws-cdk-lib';
import { ControlRunbooks } from './control_runbooks-construct';
import AdminAccountParam from '../../../lib/admin-account-param';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { IControl } from '../../../lib/sharrplaybook-construct';
import { WaitProvider } from '../../../lib/wait-provider';
import SsmDocRateLimit from '../../../lib/ssm-doc-rate-limit';

export interface NIST80053PlaybookMemberStackProps extends StackProps {
  solutionId: string;
  solutionVersion: string;
  solutionDistBucket: string;
  securityStandard: string;
  securityStandardVersion: string;
  securityStandardLongName: string;
  ssmdocs?: string;
  commonScripts?: string;
  remediations: IControl[];
}

export class NIST80053PlaybookMemberStack extends Stack {
  constructor(scope: App, id: string, props: NIST80053PlaybookMemberStackProps) {
    super(scope, id, props);

    // Not used, but required by top-level member stack
    new AdminAccountParam(this, 'AdminAccountParameter');

    const waitProviderServiceTokenParam = new CfnParameter(this, 'WaitProviderServiceToken');

    const waitProvider = WaitProvider.fromServiceToken(
      this,
      'WaitProvider',
      waitProviderServiceTokenParam.valueAsString,
    );

    Aspects.of(this).add(new SsmDocRateLimit(waitProvider));

    const controlRunbooks = new ControlRunbooks(this, 'ControlRunbooks', {
      standardShortName: props.securityStandard,
      standardLongName: props.securityStandardLongName,
      standardVersion: props.securityStandardVersion,
      runtimePython: Runtime.PYTHON_3_8, // Newest runtime for SSM automations
      solutionId: props.solutionId,
      solutionAcronym: 'ASR',
      solutionVersion: props.solutionVersion,
    });

    // Make sure all known controls have runbooks
    for (const remediation of props.remediations) {
      // Skip remapped controls
      if (remediation.executes && remediation.executes !== remediation.control) {
        continue;
      }

      if (!controlRunbooks.has(remediation.control)) {
        throw new Error(`No control runbook implemented for ${remediation.control}`);
      }
    }
  }
}

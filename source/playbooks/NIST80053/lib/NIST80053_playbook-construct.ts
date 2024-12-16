// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack, App, StackProps, CfnParameter, Aspects } from 'aws-cdk-lib';
import { ControlRunbooks } from './control_runbooks-construct';
import AdminAccountParam from '../../../lib/parameters/admin-account-param';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { IControl } from '../../../lib/sharrplaybook-construct';
import { WaitProvider } from '../../../lib/wait-provider';
import SsmDocRateLimit from '../../../lib/ssm-doc-rate-limit';
import NamespaceParam from '../../../lib/parameters/namespace-param';

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

    const namespaceParam = new NamespaceParam(this, 'Namespace');

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
      runtimePython: Runtime.PYTHON_3_11,
      solutionId: props.solutionId,
      solutionAcronym: 'ASR',
      solutionVersion: props.solutionVersion,
      remediations: props.remediations,
      namespace: namespaceParam.value,
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

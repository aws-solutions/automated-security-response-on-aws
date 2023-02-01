// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack, CfnMapping, App, StackProps } from 'aws-cdk-lib';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Trigger } from '../../../lib/ssmplaybook';
import { Construct } from 'constructs';
import { ControlRunbooks } from './control_runbooks-construct';
import { AdminAccountParm } from '../../../lib/admin_account_parm-construct';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { IControl } from '../../../lib/sharrplaybook-construct';

export interface SecurityControlsPlaybookProps extends StackProps {
  solutionId: string;
  solutionVersion: string;
  solutionDistBucket: string;
  solutionDistName: string;
  remediations: IControl[];
  securityStandard: string;
  securityStandardLongName: string;
  securityStandardVersion: string;
}

export class SecurityControlsPlaybookPrimaryStack extends Stack {
  constructor(scope: Construct, id: string, props: SecurityControlsPlaybookProps) {
    super(scope, id, props);

    const stack = Stack.of(this);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
    const orchestratorArn = StringParameter.valueForStringParameter(
      this,
      `/Solutions/${RESOURCE_PREFIX}/OrchestratorArn`
    );

    // Register the playbook. These parameters enable the step function to route matching events
    new StringParameter(this, `${props.securityStandard}ShortName`, {
      description: 'Provides a short (1-12) character abbreviation for the standard.',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/${props.securityStandardLongName}/${props.securityStandardVersion}/shortname`,
      stringValue: props.securityStandard,
    });
    new StringParameter(this, 'StandardVersion', {
      description:
        'This parameter controls whether the SHARR step function will process findings for this version of the standard.',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/${props.securityStandardLongName}/${props.securityStandardVersion}/status`,
      stringValue: 'enabled',
    });

    new CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionDistName + '/' + props.solutionVersion,
        },
      },
      lazy: true,
    });

    const processRemediation = function (controlSpec: IControl): void {
      if (controlSpec.executes != undefined && controlSpec.control != controlSpec.executes) {
        // This control is remapped to another
        new StringParameter(stack, `Remap ${props.securityStandard} ${controlSpec.control}`, {
          description: `Remap the ${props.securityStandard} ${controlSpec.control} finding to ${props.securityStandard} ${controlSpec.executes} remediation`,
          parameterName: `/Solutions/${RESOURCE_PREFIX}/${props.securityStandard}/${props.securityStandardVersion}/${controlSpec.control}/remap`,
          stringValue: `${controlSpec.executes}`,
        });
      }
      const generatorId = `control/${controlSpec.control}`;
      new Trigger(stack, `${props.securityStandard} ${controlSpec.control}`, {
        securityStandard: props.securityStandard,
        securityStandardVersion: props.securityStandardVersion,
        controlId: controlSpec.control,
        generatorId: generatorId,
        targetArn: orchestratorArn,
      });
    };

    props.remediations.forEach(processRemediation);
  }
}

export interface SecurityControlsPlaybookMemberStackProps extends StackProps {
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

export class SecurityControlsPlaybookMemberStack extends Stack {
  constructor(scope: App, id: string, props: SecurityControlsPlaybookMemberStackProps) {
    super(scope, id, props);

    // Not used, but required by top-level member stack
    new AdminAccountParm(this, 'AdminAccountParameter');

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

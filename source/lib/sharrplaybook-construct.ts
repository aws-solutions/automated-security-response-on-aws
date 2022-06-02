#!/usr/bin/env node
/*****************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/

//
// Primary Stack - launched by Service Catalog in the Security Hub Admin account
// Creates CWE rules and custom actions, orchestrator step function
// Orchestrator lambdas are common to all Playbooks and deployed in the main stack
//
import * as cdk from '@aws-cdk/core';
import { StringParameter } from '@aws-cdk/aws-ssm';
import { Trigger, SsmPlaybook } from './ssmplaybook';
import { AdminAccountParm } from './admin_account_parm-construct';
import { RunbookFactory } from '../solution_deploy/lib/runbook_factory';

export interface IControl {
    control: string;
    executes?: string;
}
export interface PlaybookProps {
    description: string;
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionDistName: string;
    remediations: IControl[];
    securityStandard: string;
    securityStandardLongName: string;
    securityStandardVersion: string;
}

export class PlaybookPrimaryStack extends cdk.Stack {

  constructor(scope: cdk.Construct, id: string, props: PlaybookProps) {
    super(scope, id, props);

    const stack = cdk.Stack.of(this)
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/,''); // prefix on every resource name
    const orchestratorArn = StringParameter.valueForStringParameter(this, `/Solutions/${RESOURCE_PREFIX}/OrchestratorArn`)

    // Register the playbook. These parameters enable the step function to route matching events
    new StringParameter(this, 'StandardShortName', {
        description: 'Provides a short (1-12) character abbreviation for the standard.',
        parameterName: `/Solutions/${RESOURCE_PREFIX}/${props.securityStandardLongName}/shortname`,
        stringValue: props.securityStandard
    });
    new StringParameter(this, 'StandardVersion', {
        description: 'This parameter controls whether the SHARR step function will process findings for this version of the standard.',
        parameterName: `/Solutions/${RESOURCE_PREFIX}/${props.securityStandardLongName}/${props.securityStandardVersion}/status`,
        stringValue: 'enabled'
    });

    new cdk.CfnMapping(this, 'SourceCode', {
        mapping: { "General": {
            "S3Bucket": props.solutionDistBucket,
            "KeyPrefix": props.solutionDistName + '/' + props.solutionVersion
        } }
    })

    const processRemediation = function(controlSpec: IControl): void {
        if ((controlSpec.executes != undefined) &&
            (controlSpec.control != controlSpec.executes)) {
            // This control is remapped to another
            new StringParameter(stack, `Remap ${props.securityStandard} ${controlSpec.control}`, {
                description: `Remap the ${props.securityStandard} ${controlSpec.control} finding to ${props.securityStandard} ${controlSpec.executes} remediation`,
                parameterName: `/Solutions/${RESOURCE_PREFIX}/${props.securityStandard}/${props.securityStandardVersion}/${controlSpec.control}/remap`,
                stringValue: `${controlSpec.executes}`
            });
        }
        let generatorId = ''
        if (props.securityStandard === 'CIS' && props.securityStandardVersion === '1.2.0') {
            // CIS 1.2.0 uses an arn-like format: arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3
            generatorId = `arn:${stack.partition}:securityhub:::ruleset/${props.securityStandardLongName}/v/${props.securityStandardVersion}/rule/${controlSpec.control}`
        }
        else {
            generatorId = `${props.securityStandardLongName}/v/${props.securityStandardVersion}/${controlSpec.control}`
        }
        new Trigger(stack, `${props.securityStandard} ${controlSpec.control}`, {
            securityStandard: props.securityStandard,
            controlId: controlSpec.control,
            generatorId: generatorId,
            targetArn: orchestratorArn
        })
    }

    props.remediations.forEach(processRemediation)

  }
}

export interface MemberStackProps {
  description: string;
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

export class PlaybookMemberStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: MemberStackProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);

    let ssmdocs = '';
    if (props.ssmdocs == undefined) {
      ssmdocs = './ssmdocs';
    } else {
      ssmdocs = props.ssmdocs;
    }

    new AdminAccountParm(this, 'AdminAccountParameter', {
      solutionId: props.solutionId
    });

    const processRemediation = function(controlSpec: IControl): void {
      // Create the ssm automation document only if this is not a remapped control
      if (!(controlSpec.executes && controlSpec.control != controlSpec.executes)) {
        RunbookFactory.createControlRunbook(stack, `${props.securityStandard} ${controlSpec.control}`, {
          securityStandard: props.securityStandard,
          securityStandardVersion: props.securityStandardVersion,
          controlId: controlSpec.control,
          ssmDocPath: ssmdocs,
          ssmDocFileName: `${props.securityStandard}_${controlSpec.control}.yaml`,
          solutionVersion: props.solutionVersion,
          solutionDistBucket: props.solutionDistBucket,
          solutionId: props.solutionId,
          commonScripts: props.commonScripts
        });
      }
    };

    props.remediations.forEach(processRemediation);
  }
}

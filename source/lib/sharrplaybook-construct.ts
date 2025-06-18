// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//
// Primary Stack - launched by Service Catalog in the Security Hub Admin account
// Creates CWE rules and custom actions, orchestrator step function
// Orchestrator lambdas are common to all Playbooks and deployed in the main stack
//
import * as cdk from 'aws-cdk-lib';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Trigger } from './ssmplaybook';
import AdminAccountParam from './parameters/admin-account-param';
import { RunbookFactory } from './runbook_factory';
import { Construct } from 'constructs';
import { Aspects, CfnParameter, StackProps } from 'aws-cdk-lib';
import { WaitProvider } from './wait-provider';
import SsmDocRateLimit from './ssm-doc-rate-limit';
import NamespaceParam from './parameters/namespace-param';

export interface IControl {
  control: string;
  versionAdded: string;
  executes?: string;
}
export interface PlaybookProps extends StackProps {
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
  constructor(scope: Construct, id: string, props: PlaybookProps) {
    super(scope, id, props);

    const stack = cdk.Stack.of(this);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
    const orchestratorArn = StringParameter.valueForStringParameter(
      this,
      `/Solutions/${RESOURCE_PREFIX}/OrchestratorArn`,
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

    new cdk.CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionDistName + '/' + props.solutionVersion,
        },
      },
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
      let generatorId = '';
      if (props.securityStandard === 'CIS' && props.securityStandardVersion === '1.2.0') {
        // CIS 1.2.0 uses an arn-like format: arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3
        generatorId = `arn:${stack.partition}:securityhub:::ruleset/${props.securityStandardLongName}/v/${props.securityStandardVersion}/rule/${controlSpec.control}`;
      } else {
        generatorId = `${props.securityStandardLongName}/v/${props.securityStandardVersion}/${controlSpec.control}`;
      }
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

export interface MemberStackProps extends StackProps {
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
  private readonly stack: cdk.Stack;
  private readonly namespace: string;
  private readonly solutionId: string;
  private readonly solutionVersion: string;
  private readonly solutionDistBucket: string;
  private readonly securityStandard: string;
  private readonly securityStandardVersion: string;
  private readonly ssmdocs: string;
  private readonly commonScripts?: string;
  private readonly remediations: IControl[];

  constructor(scope: cdk.App, id: string, props: MemberStackProps) {
    super(scope, id, props);
    this.stack = cdk.Stack.of(this);

    this.ssmdocs = '';
    if (props.ssmdocs == undefined) {
      this.ssmdocs = './ssmdocs';
    } else {
      this.ssmdocs = props.ssmdocs;
    }

    new AdminAccountParam(this, 'AdminAccountParameter');

    const namespaceParam = new NamespaceParam(this, 'Namespace');

    const waitProviderServiceTokenParam = new CfnParameter(this, 'WaitProviderServiceToken');

    const waitProvider = WaitProvider.fromServiceToken(
      this,
      'WaitProvider',
      waitProviderServiceTokenParam.valueAsString,
    );

    Aspects.of(this).add(new SsmDocRateLimit(waitProvider));

    this.namespace = namespaceParam.value;
    this.solutionId = props.solutionId;
    this.solutionVersion = props.solutionVersion;
    this.solutionId = props.solutionId;
    this.solutionDistBucket = props.solutionDistBucket;
    this.securityStandard = props.securityStandard;
    this.securityStandardVersion = props.securityStandardVersion;
    this.remediations = props.remediations;
    this.commonScripts = props.commonScripts;

    this.remediations.forEach((remediation: IControl) => this.processRemediation(remediation));
  }

  private processRemediation(controlSpec: IControl): void {
    // Create the ssm automation document only if this is not a remapped control
    if (!(controlSpec.executes && controlSpec.control != controlSpec.executes)) {
      RunbookFactory.createControlRunbook(this.stack, `${this.securityStandard} ${controlSpec.control}`, {
        securityStandard: this.securityStandard,
        securityStandardVersion: this.securityStandardVersion,
        controlId: controlSpec.control,
        ssmDocPath: this.ssmdocs,
        ssmDocFileName: `${this.securityStandard}_${controlSpec.control}.yaml`,
        solutionVersion: this.solutionVersion,
        solutionDistBucket: this.solutionDistBucket,
        solutionId: this.solutionId,
        commonScripts: this.commonScripts,
        namespace: this.namespace,
      });
    }
  }
}

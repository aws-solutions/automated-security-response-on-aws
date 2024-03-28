// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';
import { Construct } from 'constructs';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import {
  AutomationDocument,
  AutomationDocumentProps,
  AutomationStep,
  AwsApiStep,
  AwsService,
  DataTypeEnum,
  DocumentFormat,
  DocumentOutput,
  ExecuteAutomationStep,
  ExecuteScriptStep,
  HardCodedMapList,
  HardCodedString,
  HardCodedStringList,
  HardCodedStringMap,
  IGenericVariable,
  IMapListVariable,
  Input,
  IStringVariable,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringFormat,
  StringMapVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';
import { PlaybookProps } from '../lib/control_runbooks-construct';

/**
 * The scope of a remediation, `REGIONAL` or `GLOBAL`.
 *
 * @remarks
 * A remediation is `REGIONAL` if it operates on (normal) resources that exist in a single region. A remediation is
 * `GLOBAL` if it operates on global resources (e.g. IAM entities).
 *
 * A regional remediation must be executed in the same region that the resource is located. A global remediation can be
 * executed in any region. Regional remediations will have additional parameters added to the `executeAutomation` step
 * for the remediation so that it executes in the resource region. Global remediations will be executed in the region
 * where the solution admin stack is located.
 */
export enum RemediationScope {
  GLOBAL,
  REGIONAL,
}

// Properties that vary depending on what playbook/standard owns the runbook
export interface ControlRunbookProps extends PlaybookProps {
  controlId: string;
  otherControlIds?: string[];
}

// Similar to ControlRunbookProps, but allows for a parameter to be passed for runbooks that vary from standard to standard.
export interface ParameterRunbookProps extends PlaybookProps {
  controlId: string;
  otherControlIds?: string[];
  parameterToPass?: string;
}

// Properties that relate to the remediation-specific but standard-agnostic behavior of the runbook
export interface ControlRunbookDocumentProps extends AutomationDocumentProps, ControlRunbookProps {
  securityControlId: string;
  remediationName: string;
  scope: RemediationScope;
  resourceIdName?: string;
  resourceIdRegex?: string;
  updateDescription: IStringVariable;
}

export abstract class ControlRunbookDocument extends AutomationDocument {
  protected readonly controlId: string;
  protected readonly expectedControlIds: string[];
  protected readonly remediationName: string;
  protected readonly scope: RemediationScope;
  protected readonly resourceIdName: string | undefined;
  protected readonly resourceIdRegex: string | undefined;
  protected readonly updateDescription: IStringVariable;
  protected readonly runtimePython: Runtime;
  protected readonly solutionId: string;
  protected readonly solutionAcronym: string;

  constructor(stage: Construct, id: string, props: ControlRunbookDocumentProps) {
    // Policy: expect the construct id to match the control id
    if (id !== props.controlId) {
      throw new Error(`Expected construct ID (${id}) to match control ID (${props.controlId})`);
    }

    // Default values for AutomationDocumentProps if the derived class does not override them
    const defaultProps: AutomationDocumentProps = {
      documentName: `${props.solutionAcronym}-${props.standardShortName}_${props.standardVersion}_${props.controlId}`,
      description: props.description ? undefined : loadDescription(props.securityControlId),
      header: 'Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',
      assumeRole: StringVariable.of('AutomationAssumeRole'),
      documentFormat: DocumentFormat.YAML,
    };

    // If the derived class specified inputs, retain them
    const docInputs = props.docInputs ?? [];
    docInputs.push(...getInputs(props.controlId, props.remediationName, props.solutionId));
    // Likewise, if the derived class specified outputs, retain them
    const docOutputs = props.docOutputs ?? [];
    docOutputs.push(...getOutputs());

    super(stage, id, {
      ...defaultProps, // Start with default values for this document type
      ...props, // Allow overrides from the derived class
      docInputs, // Add our own inputs
      docOutputs, // Add our own outputs
      versionName: undefined, // Never specify version name, it will prevent CFN from being able to update the resource
    });

    this.controlId = props.controlId;
    this.expectedControlIds = props.otherControlIds ? [props.controlId, ...props.otherControlIds] : [props.controlId];
    this.remediationName = props.remediationName;
    this.scope = props.scope;
    this.resourceIdName = props.resourceIdName;
    this.resourceIdRegex = props.resourceIdRegex;
    this.updateDescription = props.updateDescription;
    this.runtimePython = props.runtimePython;
    this.solutionId = props.solutionId;
    this.solutionAcronym = props.solutionAcronym;

    this.cfnDocument.name = this.documentName;
    this.cfnDocument.updateMethod = 'NewVersion';
  }

  /**
   * @sealed
   * @returns The control ID for the control runbook.
   */
  public getControlId(): string {
    return this.controlId;
  }

  /** @override */
  public collectedSteps(): AutomationStep[] {
    this.builder.steps.push(this.getParseInputStep());
    this.builder.steps.push(...this.getExtraSteps());
    this.builder.steps.push(this.getRemediationStep());
    this.builder.steps.push(this.getUpdateFindingStep());

    return this.builder.steps;
  }

  /**
   * @virtual
   * @returns The `ParseInput` step to parse remediation information from the finding JSON.
   */
  protected getParseInputStep(): AutomationStep {
    const parseInputStep = new ExecuteScriptStep(this, 'ParseInput', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'parse_event'),
      code: ScriptCode.fromFile(fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'parse_input.py'))),
      inputPayload: this.getParseInputStepInputs(),
      outputs: this.getParseInputStepOutputs(),
    });

    return parseInputStep;
  }

  /**
   * @virtual
   * @returns The `getInputParams` step to parse any user customized input parameters.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getInputParamsStep(defaultParameters: { [_: string]: any }): AutomationStep {
    const getInputParamsStep = new ExecuteScriptStep(this, 'GetInputParams', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'get_input_params'),
      code: ScriptCode.fromFile(fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'get_input_params.py'))),
      inputPayload: this.getInputParamsStepInputs(defaultParameters),
      outputs: this.getInputParamsStepOutput(),
    });

    return getInputParamsStep;
  }

  /**
   * @virtual
   * @returns The inputs to the `get_input_params.py` script
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getInputParamsStepInputs(defaultParameters: { [_: string]: any }): { [_: string]: IGenericVariable } {
    return {
      SecHubInputParams: StringMapVariable.of('ParseInput.InputParams'),
      DefaultParams: HardCodedStringMap.of(defaultParameters),
    };
  }

  /**
   * @virtual
   * @returns The output values of the `ParseInput` step.
   */
  protected getParseInputStepOutputs(): Output[] {
    const affectedObjectOutput: Output = {
      name: 'AffectedObject',
      outputType: DataTypeEnum.STRING_MAP,
      selector: '$.Payload.object',
    };
    const resourceIdOutput: Output = {
      name: this.resourceIdName ?? 'ResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource_id',
    };
    const remediationAccountOutput: Output = {
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    };
    const remediationRegionOutput: Output = {
      name: 'RemediationRegion',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource_region',
    };
    const findingIdOutput: Output = {
      name: 'FindingId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.finding_id',
    };
    const productArnOutput: Output = {
      name: 'ProductArn',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.product_arn',
    };
    const inputParamsOutput: Output = {
      name: 'InputParams',
      outputType: DataTypeEnum.STRING_MAP,
      selector: '$.Payload.input_params',
    };

    const outputs: Output[] = [findingIdOutput, productArnOutput, affectedObjectOutput, inputParamsOutput];

    // Output the resource id if used
    if (this.resourceIdName) {
      outputs.push(resourceIdOutput);
    }

    // Outputs only necessary for non-global resources
    if (this.scope === RemediationScope.REGIONAL) {
      outputs.push(remediationAccountOutput, remediationRegionOutput);
    }

    return outputs;
  }

  /**
   * @virtual
   * @returns The inputs to the `parse_input.py` script
   */
  protected getParseInputStepInputs(): { [_: string]: IGenericVariable } {
    return {
      Finding: StringMapVariable.of('Finding'),
      parse_id_pattern: HardCodedString.of(this.resourceIdRegex ?? ''),
      expected_control_id: HardCodedStringList.of(this.expectedControlIds),
    };
  }

  /**
   * @virtual
   * @returns The output values of the `GetInputParams` step.
   */
  protected getInputParamsStepOutput(): Output[] {
    const inputParamsOutput: Output = {
      name: 'InputParams',
      outputType: DataTypeEnum.STRING_MAP,
      selector: '$.Payload.input_params',
    };

    const outputs: Output[] = [inputParamsOutput];

    return outputs;
  }

  /**
   * @virtual
   * @returns Additional `AutomationStep`s that must occur between the `ParseInput` and `Remediation` steps.
   */
  protected getExtraSteps(): AutomationStep[] {
    return [];
  }

  /**
   * @virtual
   * @returns The `Remediation` step to execute the remediation automation document.
   */
  protected getRemediationStep(): AutomationStep {
    const remediationDocumentName = `${this.solutionAcronym}-${this.remediationName}`;
    // For remediations on non-global resources, we should execute the remediation in the resource region
    let targetLocations: IMapListVariable | undefined = undefined;
    if (this.scope === RemediationScope.REGIONAL) {
      targetLocations = HardCodedMapList.of([
        {
          Accounts: [StringVariable.of('ParseInput.RemediationAccount')],
          Regions: [StringVariable.of('ParseInput.RemediationRegion')],
          ExecutionRoleName: StringVariable.of('RemediationRoleName'),
        },
      ]);
    }

    return new ExecuteAutomationStep(this, 'Remediation', {
      documentName: HardCodedString.of(remediationDocumentName),
      targetLocations,
      runtimeParameters: HardCodedStringMap.of(this.getRemediationParams()),
    });
  }

  /**
   * @virtual
   * @returns The parameters for the `Remediation` automation document.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = {
      AutomationAssumeRole: new StringFormat(`arn:%s:iam::%s:role/%s`, [
        StringVariable.of('global:AWS_PARTITION'),
        StringVariable.of('global:ACCOUNT_ID'),
        StringVariable.of('RemediationRoleName'),
      ]),
    };

    // Pass the resource ID only if used
    if (this.resourceIdName) {
      params[this.resourceIdName] = StringVariable.of(`ParseInput.${this.resourceIdName}`);
    }

    return params;
  }

  /**
   * @virtual
   * @returns The `UpdateFinding` step to update the status of the Security Hub finding.
   */
  protected getUpdateFindingStep(): AutomationStep {
    return new AwsApiStep(this, 'UpdateFinding', {
      service: AwsService.SECURITY_HUB,
      pascalCaseApi: 'BatchUpdateFindings',
      apiParams: {
        FindingIdentifiers: [
          {
            Id: StringVariable.of('ParseInput.FindingId'),
            ProductArn: StringVariable.of('ParseInput.ProductArn'),
          },
        ],
        Note: {
          Text: this.updateDescription,
          UpdatedBy: this.documentName,
        },
        Workflow: { Status: 'RESOLVED' },
      },
      outputs: [],
      isEnd: true,
    });
  }
}

function getInputs(controlId: string, remediationName: string, solutionId: string): Input[] {
  const inputs: Input[] = [];

  inputs.push(getFindingInput(controlId));
  inputs.push(getAutomationAssumeRoleInput());
  inputs.push(getRemediationRoleNameInput(remediationName, solutionId));

  return inputs;
}

function getFindingInput(controlId: string): Input {
  return Input.ofTypeStringMap('Finding', {
    description: `The input from the Orchestrator Step function for the ${controlId} finding`,
  });
}

function getAutomationAssumeRoleInput(): Input {
  const assumeRoleRegex = String.raw`^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[\w+=,.@-]+$`;
  return Input.ofTypeString('AutomationAssumeRole', {
    description: '(Required) The ARN of the role that allows Automation to perform the actions on your behalf.',
    allowedPattern: assumeRoleRegex,
  });
}

function getRemediationRoleNameInput(remediationName: string, solutionId: string): Input {
  const resourcePrefix = solutionId.replace(/^DEV-/, '');
  const remediationRoleName = `${resourcePrefix}-${remediationName}`;
  const remediationRoleNameRegex = String.raw`^[\w+=,.@-]+$`;
  return Input.ofTypeString('RemediationRoleName', {
    allowedPattern: remediationRoleNameRegex,
    defaultValue: remediationRoleName,
  });
}

function loadDescription(controlId: string): string {
  const descriptionPath = path.join(__dirname, 'descriptions', `${controlId}.md`);
  if (!fs.existsSync(descriptionPath)) {
    throw new Error(`Missing description at ${fs.realpathSync(descriptionPath)}`);
  }
  return fs.readFileSync(descriptionPath, { encoding: 'utf8' });
}

function getOutputs(): DocumentOutput[] {
  return [
    { name: 'Remediation.Output', outputType: DataTypeEnum.STRING_MAP },
    { name: 'ParseInput.AffectedObject', outputType: DataTypeEnum.STRING_MAP },
  ];
}

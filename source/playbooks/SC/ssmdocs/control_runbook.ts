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
  BranchStep,
  Choice,
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
  OnFailure,
  Operation,
  Output,
  ScriptLanguage,
  StringFormat,
  StringMapVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { strippedScriptCode } from '../../../lib/stripped-script-code';

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
  // Opt-in per control: only set true when the remediation runbook declares the rollback parameters.
  isRollbackEnabled?: boolean;
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
  namespace: string;
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
  protected readonly resourceNamePrefix: string;
  protected readonly namespace: string;
  protected readonly solutionAcronym: string;
  protected readonly isRollbackEnabled: boolean;

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
    docInputs.push(
      ...getInputs(
        props.controlId,
        props.remediationName,
        props.resourceNamePrefix,
        props.namespace,
        props.isRollbackEnabled ?? false,
      ),
    );
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
    this.isRollbackEnabled = props.isRollbackEnabled ?? false;
    this.updateDescription = props.updateDescription;
    this.runtimePython = props.runtimePython;
    this.solutionId = props.solutionId;
    this.resourceNamePrefix = props.resourceNamePrefix;
    this.solutionAcronym = props.solutionAcronym;
    this.namespace = props.namespace;

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

  public override collectedSteps(): AutomationStep[] {
    // On the rollback path, CheckRollback skips UpdateFinding: the Orchestrator posts the
    // authoritative rollback note (UpdatedBy 'ASR-Rollback') and resets the finding to NEW, so the
    // remediation-worded note + RESOLVED that UpdateFinding writes would be misleading. It routes the
    // rollback path straight to GetRemediationDetails; the remediation path continues to UpdateFinding.
    // CheckRollback reads {{Rollback}}, and that parameter is declared only for rollback-enabled
    // controls; SSM rejects a document that references an undeclared parameter.
    this.builder.steps.push(
      this.getParseInputStep(),
      ...this.getExtraSteps(),
      this.getRemediationStep(),
      ...(this.isRollbackEnabled ? [this.getCheckRollbackStep()] : []),
      this.getUpdateFindingStep(),
      this.getRemediationDetailsStep(),
    );

    return this.builder.steps;
  }

  /**
   * @virtual
   * @returns The `ParseInput` step to parse remediation information from the finding JSON.
   */
  protected getParseInputStep(): AutomationStep {
    const parseInputStep = new ExecuteScriptStep(this, 'ParseInput', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'parse_event'),
      code: strippedScriptCode(fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'parse_input.py'))),
      inputPayload: this.getParseInputStepInputs(),
      outputs: this.getParseInputStepOutputs(),
    });

    return parseInputStep;
  }

  /**
   * @virtual
   * @returns The `getInputParams` step to parse any user customized input parameters.
   */
  protected getInputParamsStep(defaultParameters: Record<string, any>): AutomationStep {
    const getInputParamsStep = new ExecuteScriptStep(this, 'GetInputParams', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'get_input_params'),
      code: strippedScriptCode(fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'get_input_params.py'))),
      inputPayload: this.getInputParamsStepInputs(defaultParameters),
      outputs: this.getInputParamsStepOutput(),
    });

    return getInputParamsStep;
  }

  /**
   * @virtual
   * @returns The inputs to the `get_input_params.py` script
   */
  protected getInputParamsStepInputs(defaultParameters: Record<string, any>): { [_: string]: IGenericVariable } {
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
      onFailure: OnFailure.invokeStepByName('GetRemediationDetails'),
    });
  }

  /**
   * @virtual
   * @returns The `GetRemediationDetails` step to query the child automation execution
   * and retrieve its outputs and failure message (if any).
   *
   * For REGIONAL remediations, the child execution runs in a different region than
   * the control runbook. This step uses an inline script to call GetAutomationExecution
   * in the correct target region.
   *
   * Note: The script at get_remediation_details.py is intentionally minified to reduce
   * CloudFormation template size, as it is embedded in every control runbook.
   * Type hints, docstrings, and other comments are intentionally missing.
   */
  protected getRemediationDetailsStep(): AutomationStep {
    const inputPayload: Record<string, IGenericVariable> = {
      execution_id: StringVariable.of('Remediation.ExecutionId'),
    };

    // For regional remediations, specify the target region for the API call
    if (this.scope === RemediationScope.REGIONAL) {
      inputPayload['target_region'] = StringVariable.of('ParseInput.RemediationRegion');
    }

    return new ExecuteScriptStep(this, 'GetRemediationDetails', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'get_remediation_details'),
      code: strippedScriptCode(
        fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'get_remediation_details.py')),
      ),
      inputPayload,
      outputs: [
        {
          name: 'Output',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.outputs',
        },
        {
          name: 'FailureMessage',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.failure_message',
        },
      ],
      isEnd: true,
    });
  }

  /**
   * @virtual
   * @returns The parameters for the `Remediation` automation document.
   */
  protected getRemediationParams(): Record<string, any> {
    // Forwarding the rollback params to a control whose remediation runbook doesn't declare them makes
    // SSM reject StartAutomationExecution with "Undefined execution inputs" — so gate them on the flag.
    const rollbackParams: Record<string, any> = this.isRollbackEnabled
      ? {
          Rollback: StringVariable.of('Rollback'),
          ExecutionId: StringVariable.of('ExecutionId'),
          RemediationConfigBucket: StringVariable.of('RemediationConfigBucket'),
          ControlExecutionId: StringVariable.of('automation:EXECUTION_ID'),
          SnapshotVersionId: StringVariable.of('SnapshotVersionId'),
        }
      : {};

    const resourceIdParam: Record<string, any> = this.resourceIdName
      ? { [this.resourceIdName]: StringVariable.of(`ParseInput.${this.resourceIdName}`) }
      : {};

    return {
      AutomationAssumeRole: new StringFormat(`arn:%s:iam::%s:role/%s`, [
        StringVariable.of('global:AWS_PARTITION'),
        StringVariable.of('global:ACCOUNT_ID'),
        StringVariable.of('RemediationRoleName'),
      ]),
      ...rollbackParams,
      ...resourceIdParam,
    };
  }

  /**
   * @returns A `CheckRollback` branch step. On the remediation path (`Rollback` == '') it proceeds to
   * `UpdateFinding`; on the rollback path it jumps to `GetRemediationDetails`, skipping `UpdateFinding`
   * so the misleading remediation note / RESOLVED status is not written (the Orchestrator owns finding
   * state on rollback).
   */
  protected getCheckRollbackStep(): AutomationStep {
    return new BranchStep(this, 'CheckRollback', {
      choices: [
        new Choice({
          operation: Operation.STRING_EQUALS,
          constant: '',
          variable: StringVariable.of('Rollback'),
          jumpToStepName: 'UpdateFinding',
        }),
      ],
      defaultStepName: 'GetRemediationDetails',
    });
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
    });
  }
}

function getInputs(
  controlId: string,
  remediationName: string,
  resourceNamePrefix: string,
  namespace: string,
  isRollbackEnabled: boolean,
): Input[] {
  const inputs: Input[] = [];

  inputs.push(
    getFindingInput(controlId),
    getAutomationAssumeRoleInput(),
    getRemediationRoleNameInput(remediationName, resourceNamePrefix, namespace),
  );

  if (isRollbackEnabled) {
    inputs.push(
      Input.ofTypeString('Rollback', {
        description: '(Optional) Set to ROLLBACK to execute rollback instead of remediation.',
        defaultValue: '',
        allowedValues: ['', 'ROLLBACK'],
      }),
      Input.ofTypeString('ExecutionId', {
        description: '(Optional) Original SSM Automation execution ID for snapshot lookup during rollback.',
        defaultValue: '',
      }),
      Input.ofTypeString('RemediationConfigBucket', {
        description: '(Optional) S3 bucket name for snapshot storage. Resolved from SSM parameter by default.',
        defaultValue: '{{ssm:/Solutions/SO0111/RemediationConfigurationBucket}}',
      }),
      Input.ofTypeString('SnapshotVersionId', {
        description: '(Optional) S3 version ID of the snapshot object for tamper-proof reads during rollback.',
        defaultValue: '',
      }),
    );
  }

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

function getRemediationRoleNameInput(remediationName: string, resourceNamePrefix: string, namespace: string): Input {
  const remediationRoleName = `${resourceNamePrefix}-${remediationName}-${namespace}`;
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
    { name: 'GetRemediationDetails.Output', outputType: DataTypeEnum.STRING },
    { name: 'GetRemediationDetails.FailureMessage', outputType: DataTypeEnum.STRING },
  ];
}

/**
 * Thrown when a method that is intentionally unsupported is called.
 * Used in place of generic `Error` to make the intent explicit and
 * allow callers to distinguish unsupported-operation failures from
 * other runtime errors.
 */
export class UnsupportedOperationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedOperationError';
  }
}

/**
 * Base class for control runbooks that use a single-step architecture.
 *
 * Inspector, GuardDuty.IAMUser, and Macie.SensitiveDataS3Object all perform
 * their full remediation logic inline in the ParseInput script rather than
 * invoking a separate remediation runbook. They share identical boilerplate:
 * - The base class appends Remediation/GetRemediationDetails outputs that
 *   reference non-existent steps, so docOutputs must be replaced after super().
 * - collectedSteps() only pushes the single ParseInput step.
 * - getRemediationStep() and getRemediationParams() are not used.
 *
 * Concrete subclasses only need to implement getParseInputStep() and
 * getParseInputStepOutputs().
 */
export abstract class SingleStepControlRunbookDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookDocumentProps) {
    super(scope, id, props);

    // The base class appends Remediation.Output and GetRemediationDetails.*
    // to docOutputs after merging with props.docOutputs. Replace the array
    // to remove outputs referencing non-existent steps — SSM rejects documents
    // with outputs referencing unknown steps.
    this.docOutputs.length = 0;
    this.docOutputs.push(
      { name: 'ParseInput.AffectedObject', outputType: DataTypeEnum.STRING_MAP },
      { name: 'ParseInput.Status', outputType: DataTypeEnum.STRING },
      { name: 'ParseInput.Message', outputType: DataTypeEnum.STRING },
      ...this.getAdditionalDocumentOutputs(),
    );
  }

  /**
   * Document-level outputs beyond the shared ParseInput.AffectedObject/Status/Message.
   * Document outputs surface in the SSM GetAutomationExecution response that the
   * Orchestrator reads, so a subclass must declare any ParseInput output it needs
   * the Orchestrator to consume (e.g. GuardDuty.IAMUser's BackupS3Key). Each name
   * must reference a real ParseInput step output or SSM rejects the document.
   */
  protected getAdditionalDocumentOutputs(): DocumentOutput[] {
    return [];
  }

  public override collectedSteps(): AutomationStep[] {
    this.builder.steps.push(this.getParseInputStep());
    return this.builder.steps;
  }

  /**
   * Concrete subclasses must override this to provide their control-specific
   * inline script. Declared abstract here so that forgetting to override it
   * causes a compile error rather than silently falling back to the base class
   * implementation (which calls parse_input.py instead of the control script).
   */
  protected abstract override getParseInputStep(): ExecuteScriptStep;

  protected override getRemediationStep(): AutomationStep {
    throw new UnsupportedOperationError(
      `getRemediationStep should not be called for ${this.controlId}. ` +
        'This control uses a single-step architecture via collectedSteps().',
    );
  }

  protected override getRemediationParams(): Record<string, any> {
    return {};
  }
}

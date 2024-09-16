// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { RegexRegistry, getRegexRegistry } from './regex_registry';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

class RunbookTestHelper {
  _file: string;
  _contents: string | undefined;
  _contentsAsLines: string[] | undefined;
  _contentsAsObject: any | undefined; // eslint-disable-line @typescript-eslint/no-explicit-any
  _validVariables: Set<string> | undefined;

  constructor(file: string) {
    this._file = file;
  }

  getFile(): string {
    return this._file;
  }

  isRemediationRunbook(): boolean {
    const parent: string | undefined = path.dirname(this._file).split(path.sep).pop();
    return parent === 'remediation_runbooks';
  }

  getContents(): string {
    if (this._contents === undefined) {
      this._contents = fs.readFileSync(this._file, 'utf8');
    }
    return this._contents || '';
  }

  getLines(): string[] {
    if (this._contentsAsLines === undefined) {
      this._contentsAsLines = this.getContents().split('\n');
    }
    return this._contentsAsLines || [];
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getObject(): any {
    if (this._contentsAsObject === undefined) {
      this._contentsAsObject = yaml.load(this.getContents());
    }
    return this._contentsAsObject;
  }

  toString(): string {
    return this._file;
  }

  getValidVariables(): Set<string> {
    if (this._validVariables !== undefined) {
      return this._validVariables;
    }
    this._validVariables = new Set();
    for (const parameter of Object.keys(this.getObject().parameters)) {
      if (this._validVariables.has(parameter)) {
        throw Error(`Duplicate parameter: ${parameter}`);
      }
      this._validVariables.add(parameter);
    }
    for (const step of this.getObject().mainSteps) {
      const name: string = step.name;
      if (step.outputs !== undefined) {
        for (const output of step.outputs) {
          const variable = `${name}.${output.Name}`;
          if (this._validVariables.has(variable)) {
            throw Error(`Duplicate step output: ${variable}`);
          }
          this._validVariables.add(variable);
        }
      }
    }
    const globals: string[] = ['global:ACCOUNT_ID', 'global:REGION', 'global:AWS_PARTITION'];
    for (const global of globals) {
      this._validVariables.add(global);
    }
    return this._validVariables;
  }

  getStandardName(): string {
    if (this.isRemediationRunbook()) {
      throw Error('Remediation runbooks are not aware of standards');
    }
    return path.dirname(path.dirname(this._file)).split(path.sep).pop() || '';
  }

  getDocumentName(): string {
    return path.basename(this._file, path.extname(this._file));
  }

  getControlName(): string {
    if (this.isRemediationRunbook()) {
      throw Error('Remediation runbooks are not aware of controls');
    }
    const standard: string = this.getStandardName();
    switch (standard) {
      case 'AFSBP':
        return this.getDocumentName().substring(6);
      case 'CIS120':
        return this.getDocumentName().substring(4);
      case 'PCI321':
        return this.getDocumentName().substring(4);
      default:
        throw Error(`Unrecognized standard: ${standard}`);
    }
  }
}

function getRunbooksFromDirectories(directories: string[], exclusions: string[]): RunbookTestHelper[] {
  const result: RunbookTestHelper[] = [];
  for (const directory of directories) {
    const directoryContents: string[] = fs.readdirSync(directory);
    for (const filename of directoryContents) {
      if (exclusions.includes(filename)) {
        continue;
      }
      const file = path.join(directory, filename);
      const stats: fs.Stats = fs.statSync(file);
      if (stats.isFile()) {
        const extension: string | undefined = filename.split('.').pop()?.toLowerCase();
        if (extension == 'yaml' || extension == 'yml') {
          result.push(new RunbookTestHelper(file));
        }
      }
    }
  }
  return result;
}

function getControlRunbooks(runbooks: RunbookTestHelper[]): RunbookTestHelper[] {
  const result: RunbookTestHelper[] = [];
  for (const runbook of runbooks) {
    if (!runbook.isRemediationRunbook()) {
      result.push(runbook);
    }
  }
  return result;
}

function getRemediationRunbooks(runbooks: RunbookTestHelper[]): RunbookTestHelper[] {
  const result: RunbookTestHelper[] = [];
  for (const runbook of runbooks) {
    if (runbook.isRemediationRunbook()) {
      result.push(runbook);
    }
  }
  return result;
}

// Tests run from the source directory
const runbookDirectories: string[] = [
  './playbooks/AFSBP/ssmdocs',
  './playbooks/CIS120/ssmdocs',
  './playbooks/PCI321/ssmdocs',
  './remediation_runbooks',
];

// Documents that are copies of AWS Config remediation documents can temporarily be excluded from tests
// Do not add other runbooks to this list
// TODO all remediation documents should eventually be tested
const excludedRunbooks: string[] = [
  'ConfigureS3BucketPublicAccessBlock.yaml',
  'ConfigureS3PublicAccessBlock.yaml',
  'DisablePublicAccessToRDSInstance.yaml',
  'EnableCloudTrailLogFileValidation.yaml',
  'EnableEbsEncryptionByDefault.yaml',
  'EnableEnhancedMonitoringOnRDSInstance.yaml',
  'EnableKeyRotation.yaml',
  'EnableRDSClusterDeletionProtection.yaml',
  'RemoveVPCDefaultSecurityGroupRules.yaml',
  'RevokeUnusedIAMUserCredentials.yaml',
  'SetIAMPasswordPolicy.yaml',
];

const runbooks: RunbookTestHelper[] = getRunbooksFromDirectories(runbookDirectories, excludedRunbooks);
const controlRunbooks: RunbookTestHelper[] = getControlRunbooks(runbooks);
const remediationRunbooks = getRemediationRunbooks(runbooks);

const regexRegistry: RegexRegistry = getRegexRegistry();

test.skip.each(runbooks)('%s has copyright header', (runbook: RunbookTestHelper) => {
  expect(runbook.getLines().slice(0, 2)).toStrictEqual([
    '# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.',
    '# SPDX-License-Identifier: Apache-2.0',
  ]);
});

test.skip.each(runbooks)('%s has begin document indicator', (runbook: RunbookTestHelper) => {
  expect(runbook.getLines()[2]).toStrictEqual('---');
});

test.skip.each(runbooks)('%s ends with newline', (runbook: RunbookTestHelper) => {
  expect(runbook.getLines().pop()).toStrictEqual('');
});

test.each(runbooks)('%s has correct schema version', (runbook: RunbookTestHelper) => {
  expect(runbook.getObject().schemaVersion).toStrictEqual('0.3');
});

function getExpectedDocumentName(runbook: RunbookTestHelper): string {
  if (runbook.isRemediationRunbook()) {
    return `ASR-${runbook.getDocumentName()}`;
  }
  const standard: string = runbook.getStandardName();
  switch (standard) {
    case 'AFSBP':
      return `ASR-AFSBP_1.0.0_${runbook.getControlName()}`;
    case 'CIS120':
      return `ASR-CIS_1.2.0_${runbook.getControlName()}`;
    case 'PCI321':
      return `ASR-PCI_3.2.1_${runbook.getControlName()}`;
    default:
      throw Error(`Unrecognized standard: ${standard}`);
  }
}

test.skip.each(runbooks)('%s description has correct document name', (runbook: RunbookTestHelper) => {
  const expectedName = getExpectedDocumentName(runbook);
  const description: string = runbook.getObject().description;
  expect(description.split('\n')[0]).toStrictEqual(`### Document Name - ${expectedName}`);
});

function sectionNotEmpty(description: string, header: string) {
  const lines: string[] = description.split('\n');
  let headerFound = false;
  let nonBlankLines = 0;
  for (const line of lines) {
    if (!headerFound) {
      if (line === header) {
        headerFound = true;
      }
    } else if (line === '' || line.startsWith('#')) {
      break;
    } else {
      ++nonBlankLines;
    }
  }
  return nonBlankLines > 0;
}

function descriptionHasExplanation(description: string): boolean {
  return sectionNotEmpty(description, '## What does this document do?');
}

test.each(runbooks)('%s description has explanation', (runbook: RunbookTestHelper) => {
  const description: string = runbook.getObject().description;
  expect(descriptionHasExplanation(description)).toBe(true);
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function descriptionDocumentsInputParameters(description: string, parameters: any): boolean {
  if (!parameters) {
    return true;
  }
  const expectedDoc: Set<string> = new Set();
  for (const [name, details] of Object.entries(parameters)) {
    expectedDoc.add(`* ${name}: ${(details as any).description}`); // eslint-disable-line @typescript-eslint/no-explicit-any
  }
  const lines: string[] = description.split('\n');
  let inputParametersHeaderFound = false;
  const actualDoc: Set<string> = new Set();
  for (const line of lines) {
    if (!inputParametersHeaderFound) {
      if (line === '## Input Parameters') {
        inputParametersHeaderFound = true;
      }
    } else if (line === '' || line.startsWith('##')) {
      // The section has ended
      break;
    } else {
      actualDoc.add(line);
    }
  }
  if (expectedDoc.size != actualDoc.size) {
    return false;
  }
  for (const element of expectedDoc) {
    if (!actualDoc.has(element)) {
      return false;
    }
  }
  return true;
}

test.skip.each(runbooks)('%s description documents input parameters', (runbook: RunbookTestHelper) => {
  const description: string = runbook.getObject().description;
  const parameters: any = runbook.getObject().parameters; // eslint-disable-line @typescript-eslint/no-explicit-any
  expect(descriptionDocumentsInputParameters(description, parameters)).toBe(true);
});

function descriptionDocumentsOutputParameters(description: string, outputs: string[]) {
  if (!outputs) {
    return true;
  }
  const expectedDoc: Set<string> = new Set();
  for (const output of outputs) {
    expectedDoc.add(`* ${output}`);
  }
  const lines: string[] = description.split('\n');
  let outputParametersHeaderFound = false;
  const actualDoc: Set<string> = new Set();
  for (const line of lines) {
    if (!outputParametersHeaderFound) {
      if (line === '## Output Parameters') {
        outputParametersHeaderFound = true;
      }
    } else if (line === '' || line.startsWith('##')) {
      // The section has ended
      break;
    } else {
      actualDoc.add(line);
    }
  }
  if (expectedDoc.size != actualDoc.size) {
    return false;
  }
  for (const element of expectedDoc) {
    if (!actualDoc.has(element)) {
      return false;
    }
  }
  return true;
}

test.skip.each(runbooks)('%s description documents output parameters', (runbook: RunbookTestHelper) => {
  const description: string = runbook.getObject().description;
  const outputs: any = runbook.getObject().outputs; // eslint-disable-line @typescript-eslint/no-explicit-any
  expect(descriptionDocumentsOutputParameters(description, outputs)).toBe(true);
});

function descriptionHasDocumentationLinks(description: string) {
  return sectionNotEmpty(description, '## Documentation Links');
}

test.skip.each(controlRunbooks)('%s description has documentation links', (runbook: RunbookTestHelper) => {
  const description: string = runbook.getObject().description;
  expect(descriptionHasDocumentationLinks(description)).toBe(true);
});

function desriptionDocumentsSecurityStandards(description: string): boolean {
  return sectionNotEmpty(description, '## Security Standards / Controls');
}

test.skip.each(remediationRunbooks)(
  '%s description documents security standards and controls',
  (runbook: RunbookTestHelper) => {
    const description: string = runbook.getObject().description;
    expect(desriptionDocumentsSecurityStandards(description)).toBe(true);
  },
);

function isAssumeRoleParameter(value: string): boolean {
  return value === '{{ AutomationAssumeRole }}' || value == '{{AutomationAssumeRole}}';
}

test.each(runbooks)('%s takes AssumeRole as parameter', (runbook: RunbookTestHelper) => {
  expect(isAssumeRoleParameter(runbook.getObject().assumeRole)).toBe(true);
  expect(runbook.getObject().parameters.AutomationAssumeRole.type).toStrictEqual('String');
  expect(runbook.getObject().parameters.AutomationAssumeRole.description).toStrictEqual(
    '(Required) The ARN of the role that allows Automation to perform the actions on your behalf.',
  );
  expect(runbook.getObject().parameters.AutomationAssumeRole).not.toHaveProperty('default');
  expect(runbook.getObject().parameters.AutomationAssumeRole.allowedPattern).toStrictEqual(
    regexRegistry.getRegexForAutomationAssumeRole(),
  );
});

test.skip.each(controlRunbooks)('%s has correct outputs', (runbook: RunbookTestHelper) => {
  expect(runbook.getObject().outputs).toStrictEqual(['Remediation.Output', 'ParseInput.AffectedObject']);
});

test.skip.each(remediationRunbooks)('%s has outputs', (runbook: RunbookTestHelper) => {
  expect(runbook.getObject().outputs).toBeTruthy();
});

test.each(controlRunbooks)('%s takes finding as parameter', (runbook: RunbookTestHelper) => {
  expect(runbook.getObject().parameters.Finding.type).toStrictEqual('StringMap');
  expect(runbook.getObject().parameters.Finding.description).toStrictEqual(
    `The input from the Orchestrator Step function for the ${runbook.getControlName()} finding`,
  );
});

test.each(runbooks)('%s takes valid parameters', (runbook: RunbookTestHelper) => {
  // https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-doc-syntax.html
  const parameters: any = runbook.getObject().parameters; // eslint-disable-line @typescript-eslint/no-explicit-any
  if (!parameters) {
    return;
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for (const [_, detailsObj] of Object.entries(parameters)) {
    const details = detailsObj as any; // eslint-disable-line @typescript-eslint/no-explicit-any
    switch (details.type) {
      case 'String':
        // String parameters must be validated
        expect(details.allowedPattern || details.allowedValues).toBeTruthy();
        if (details.allowedPattern) {
          // Regular expressions must be tested
          expect(regexRegistry.has(details.allowedPattern)).toBe(true);
        }
        break;
      case 'StringList':
        break;
      case 'Integer':
        break;
      case 'Boolean':
        break;
      case 'MapList':
        break;
      case 'StringMap':
        break;
      default:
        throw Error(`Unrecognized type: ${details.type}`);
    }
  }
  // TODO: check that default values, if provided, are the correct type
  // TODO: require descriptions
  // TODO: disallow .*
});

test.each(controlRunbooks)('%s has valid parse input step', (runbook: RunbookTestHelper) => {
  const steps: any = runbook.getObject().mainSteps; // eslint-disable-line @typescript-eslint/no-explicit-any
  const parseStep = steps[0];
  expect(parseStep.name).toStrictEqual('ParseInput');
  expect(parseStep.action).toStrictEqual('aws:executeScript');
  expect(parseStep.inputs.Handler).toStrictEqual('parse_event');
  expect(parseStep.inputs.Script).toStrictEqual('%%SCRIPT=common/parse_input.py%%');
  expect(parseStep.inputs.InputPayload.Finding).toStrictEqual('{{Finding}}');
  const parseIdPattern: string = parseStep.inputs.InputPayload.parse_id_pattern;
  // Empty parse ID pattern is ok if no information needs to be extracted from the finding resource ID
  if (parseIdPattern !== '') {
    // Patterns must be tested
    expect(regexRegistry.has(parseIdPattern)).toBe(true);
  }
  const expectedControlId: any = parseStep.inputs.InputPayload.expected_control_id; // eslint-disable-line @typescript-eslint/no-explicit-any
  expect(Array.isArray(expectedControlId)).toBe(true);
  expect(expectedControlId as string[]).toEqual(expect.arrayContaining([runbook.getControlName()]));
  // TODO match known outputs of parse_input and types
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function validateScriptStep(runbook: RunbookTestHelper, step: any) {
  if (step.outputs) {
    for (const output of step.outputs) {
      // capturing the entire output with '$' is ok
      if (output.Selector !== '$') {
        // selectors must have the correct prefix
        expect(output.Selector).toMatch(/\$\.Payload.*/);
      }
    }
  }
  // TODO scripts must be templates that link to files
  expect(step.inputs.Runtime).toStrictEqual('python3.11');
}

test.each(runbooks)('%s has valid steps', (runbook: RunbookTestHelper) => {
  const steps: any[] = runbook.getObject().mainSteps; // eslint-disable-line @typescript-eslint/no-explicit-any
  // Must have at least one step
  expect(steps.length).toBeGreaterThan(0);
  for (const step of steps) {
    const stepName: string = step.name;
    // Must have name
    expect(stepName.length).toBeGreaterThan(0);
    const stepAction: string = step.action;
    switch (stepAction) {
      case 'aws:executeScript':
        validateScriptStep(runbook, step);
        break;
      case 'aws:executeAutomation':
        // TODO
        break;
      case 'aws:executeAwsApi':
        // TODO
        break;
      case 'aws:waitForAwsResourceProperty':
        // TODO
        break;
      case 'aws:assertAwsResourceProperty':
        // TODO
        break;
      case 'aws:branch':
        // TODO
        break;
      default:
        throw Error(`Unrecognized step action: ${stepAction}`);
    }
  }
});

function isSsmParameter(parameter: string): boolean {
  return parameter.startsWith('ssm:/');
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function validateTemplateVariablesRecursive(obj: any, runbook: RunbookTestHelper) {
  if (obj === undefined || obj === null) {
    return;
  } else if (typeof obj === 'string') {
    const objAsString: string = obj as string;
    const regex = /(?<={{)(.*?)(?=}})/g;
    let matches;
    while ((matches = regex.exec(objAsString))) {
      const match: string = matches[1].trim();
      if (!isSsmParameter(match)) {
        expect(runbook.getValidVariables()).toContain(match);
      }
    }
  } else if (typeof obj[Symbol.iterator] === 'function') {
    for (const element of obj) {
      validateTemplateVariablesRecursive(element, runbook);
    }
  } else {
    for (const value of Object.values(obj)) {
      validateTemplateVariablesRecursive(value, runbook);
    }
  }
}

test.each(runbooks)('%s has valid template variables', (runbook: RunbookTestHelper) => {
  validateTemplateVariablesRecursive(runbook.getObject(), runbook);
});

test.skip.each(runbooks)('%s has valid output variables', (runbook: RunbookTestHelper) => {
  if (runbook.getObject().outputs) {
    for (const output of runbook.getObject().outputs) {
      expect(runbook.getValidVariables()).toContain(output);
    }
  }
});

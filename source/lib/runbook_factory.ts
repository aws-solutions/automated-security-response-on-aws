// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'fs';
import * as cdk from 'aws-cdk-lib';
import { Policy } from 'aws-cdk-lib/aws-iam';
import { CfnDocument } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import * as yaml from 'js-yaml';

export interface IssmPlaybookProps {
  securityStandard: string; // ex. AFSBP
  securityStandardVersion: string;
  controlId: string;
  ssmDocPath: string;
  ssmDocFileName: string;
  solutionVersion: string;
  solutionDistBucket: string;
  adminRoleName?: string;
  remediationPolicy?: Policy;
  adminAccountNumber?: string;
  solutionId: string;
  scriptPath?: string;
  commonScripts?: string;
  namespace: string;
}

export interface RemediationRunbookProps {
  ssmDocName: string;
  ssmDocPath: string;
  ssmDocFileName: string;
  solutionVersion: string;
  solutionDistBucket: string;
  remediationPolicy?: Policy;
  solutionId: string;
  scriptPath?: string;
  namespace: string;
}

interface ScriptLineGroups {
  script: string;
  padding: string;
}

interface RoleLineGroups {
  prefix: string;
  role: string;
  suffix: string;
}

export class RunbookFactory extends Construct {
  constructor(scope: Construct, id: string) {
    super(scope, id);
  }

  static createControlRunbook(scope: Construct, id: string, props: IssmPlaybookProps): CfnDocument {
    const scriptPath = props.scriptPath ?? `${props.ssmDocPath}/scripts`;
    const commonScripts = props.commonScripts ?? '../common';

    const enableParam = new cdk.CfnParameter(scope, `Enable ${props.controlId}`, {
      type: 'String',
      description: `Enable/disable availability of remediation for ${props.securityStandard} version ${props.securityStandardVersion} Control ${props.controlId} in Security Hub Console Custom Actions. If NOT Available the remediation cannot be triggered from the Security Hub console in the Security Hub Admin account.`,
      default: 'Available',
      allowedValues: ['Available', 'NOT Available'],
    });
    const installSsmDoc = new cdk.CfnCondition(scope, `Enable ${props.controlId} Condition`, {
      expression: cdk.Fn.conditionEquals(enableParam, 'Available'),
    });

    const ssmDocName = `ASR-${props.securityStandard}_${props.securityStandardVersion}_${props.controlId}`;
    const ssmDocType = props.ssmDocFileName.slice(-4).toLowerCase();

    const ssmDocContent = this.generateControlRunbookDocContent(props, scriptPath, commonScripts);
    const ssmDoc = new CfnDocument(scope, `Control ${id}`, {
      name: ssmDocName,
      content: yaml.load(ssmDocContent),
      documentFormat: ssmDocType.toUpperCase(),
      documentType: 'Automation',
      updateMethod: 'NewVersion',
    });
    ssmDoc.cfnOptions.condition = installSsmDoc;
    return ssmDoc;
  }

  private static generateControlRunbookDocContent(
    props: IssmPlaybookProps,
    scriptPath: string,
    commonScripts: string,
  ): string {
    const ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`;
    const ssmDocIn = readFileSync(ssmDocFQFileName, 'utf8');
    const scriptRegex = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/; // NOSONAR: Allowed to use named groups
    const assumeRoleRegex = /^(?<prefix>.*)%%ROLE=(?<role>.*)%%(?<suffix>.*)/; // NOSONAR: Allowed to use named groups
    let ssmDocOut = '';
    for (const line of ssmDocIn.split('\n')) {
      const foundScriptMatch = scriptRegex.exec(line);
      const foundRoleMatch = assumeRoleRegex.exec(line);
      if (foundScriptMatch?.groups?.script) {
        ssmDocOut += this.processScriptLine(foundScriptMatch, scriptPath, commonScripts);
      } else if (foundRoleMatch?.groups?.role) {
        ssmDocOut += this.processRoleLine(foundRoleMatch, props);
      } else {
        ssmDocOut += line + '\n';
      }
    }
    return ssmDocOut;
  }

  static createRemediationRunbook(scope: Construct, id: string, props: RemediationRunbookProps) {
    const ssmDocName = `ASR-${props.ssmDocName}`;
    const ssmDocType = props.ssmDocFileName.substring(props.ssmDocFileName.length - 4).toLowerCase();
    const scriptPath = props.scriptPath || 'ssmdocs/scripts';
    const commonScripts = `${scriptPath}/common`;

    const ssmDocContent = this.generateRemediationRunbookDocContent(props, scriptPath, commonScripts);

    return new CfnDocument(scope, id, {
      content: yaml.load(ssmDocContent),
      documentFormat: ssmDocType.toUpperCase(),
      documentType: 'Automation',
      name: ssmDocName,
      updateMethod: 'NewVersion',
    });
  }

  private static generateRemediationRunbookDocContent(
    props: RemediationRunbookProps,
    scriptPath: string,
    commonScripts: string,
  ): string {
    const ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`;
    const ssmDocIn = readFileSync(ssmDocFQFileName, 'utf8');
    let ssmDocOut = '';
    const scriptRegex = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/; // NOSONAR: Allowed to use named groups
    const assumeRoleRegex = /^(?<prefix>.*)%%ROLE=(?<role>.*)%%(?<suffix>.*)/; // NOSONAR: Allowed to use named groups

    for (const line of ssmDocIn.split('\n')) {
      const foundScriptMatch = scriptRegex.exec(line);
      const foundRoleMatch = assumeRoleRegex.exec(line);
      if (foundScriptMatch?.groups?.script) {
        ssmDocOut += this.processScriptLine(foundScriptMatch, scriptPath, commonScripts);
      } else if (foundRoleMatch?.groups?.role) {
        ssmDocOut += this.processRoleLine(foundRoleMatch, props);
      } else {
        ssmDocOut += line + '\n';
      }
    }

    return ssmDocOut;
  }

  private static processScriptLine(
    foundScriptMatch: RegExpExecArray,
    scriptPath: string,
    commonScripts?: string,
  ): string {
    const { padding, script } = foundScriptMatch.groups as unknown as ScriptLineGroups;
    const commonPrefix = 'common/';
    const pathAndFileToInsert = script.startsWith(commonPrefix)
      ? `${commonScripts}/${script.replace(commonPrefix, '')}`
      : `${scriptPath}/${script}`;
    const scriptIn = readFileSync(pathAndFileToInsert, 'utf8');
    const resolvedScript = this.resolveIncludes(scriptIn, scriptPath, commonScripts);
    return (
      resolvedScript
        .split('\n')
        .map((scriptLine) => `${padding}${scriptLine}`)
        .join('\n') + '\n'
    );
  }

  static resolveIncludes(scriptContent: string, scriptPath: string, commonScripts?: string): string {
    const includeRegex = /^#?\s*%%INCLUDE=(?<file>.*)%%$/; // NOSONAR: Allowed to use named groups
    const lines = scriptContent.split('\n');
    const resolved: string[] = [];
    for (const line of lines) {
      const match = includeRegex.exec(line.trim());
      if (match?.groups?.file) {
        const commonPrefix = 'common/';
        const includePath = match.groups.file.startsWith(commonPrefix)
          ? `${commonScripts}/${match.groups.file.replace(commonPrefix, '')}`
          : `${scriptPath}/${match.groups.file}`;
        const includeContent = readFileSync(includePath, 'utf8');
        // Strip the test-time `from common...` import (fenced by `# fmt: off`/`# fmt: on`) before
        // embedding: at SSM runtime the module is inlined below, not importable. The import may span
        // multiple lines (black wraps long imports), so strip the whole fence, not a fixed size.
        const isFmtOff = (s: string): boolean => /^#\s*fmt:\s*off$/.test(s.trim());
        const isFmtOn = (s: string): boolean => /^#\s*fmt:\s*on$/.test(s.trim());
        const fenceEnd = resolved.length - 1;
        if (fenceEnd >= 0 && isFmtOn(resolved[fenceEnd])) {
          let fenceStart = fenceEnd - 1;
          while (fenceStart >= 0 && !isFmtOff(resolved[fenceStart])) {
            fenceStart--;
          }
          const fenceBody = fenceStart >= 0 ? resolved.slice(fenceStart + 1, fenceEnd) : [];
          // The shim is always `# fmt: off` immediately followed by the `from common...` import. Require
          // that shape (first non-blank line inside the fence is the import) so a distant, unrelated
          // `# fmt: off` further up the file can't cause a large unrelated block to be spliced out.
          const firstNonBlank = fenceBody.find((l) => l.trim() !== '');
          const isTestImportBlock =
            firstNonBlank !== undefined && /^from\s+common\.\w+\s+import/.test(firstNonBlank.trim());
          if (isTestImportBlock) {
            resolved.splice(fenceStart, fenceEnd - fenceStart + 1);
          }
        }
        resolved.push(includeContent.replace(/\n$/, ''));
      } else {
        resolved.push(line);
      }
    }
    return resolved.join('\n');
  }

  private static processRoleLine(
    foundRoleMatch: RegExpExecArray,
    props: RemediationRunbookProps | IssmPlaybookProps,
  ): string {
    const { prefix, role, suffix } = foundRoleMatch.groups as unknown as RoleLineGroups;
    const roleName = `${role}-${props.namespace}`;
    return `${prefix}${roleName}${suffix}\n`;
  }
}

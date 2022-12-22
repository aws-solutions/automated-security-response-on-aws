#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IssmPlaybookProps, RemediationRunbookProps } from '../../lib/ssmplaybook';
import { CfnDocument } from '@aws-cdk/aws-ssm';
import * as cdk from '@aws-cdk/core';
import * as fs from 'fs';
import * as yaml from 'js-yaml';

export class RunbookFactory extends cdk.Construct {
  constructor(scope: cdk.Construct, id: string) {
    super(scope, id);
  }

  static createControlRunbook(scope: cdk.Construct, id: string, props: IssmPlaybookProps): CfnDocument {
    let scriptPath = '';
    if (props.scriptPath == undefined ) {
      scriptPath = `${props.ssmDocPath}/scripts`;
    } else {
      scriptPath = props.scriptPath;
    }

    let commonScripts = '';
    if (props.commonScripts == undefined ) {
      commonScripts = '../common';
    } else {
      commonScripts = props.commonScripts;
    }

    const enableParam = new cdk.CfnParameter(scope, 'Enable ' + props.controlId, {
      type: 'String',
      description: `Enable/disable availability of remediation for ${props.securityStandard} version ${props.securityStandardVersion} Control ${props.controlId} in Security Hub Console Custom Actions. If NOT Available the remediation cannot be triggered from the Security Hub console in the Security Hub Admin account.`,
      default: 'Available',
      allowedValues: ['Available', 'NOT Available']
    });

    const installSsmDoc = new cdk.CfnCondition(scope, 'Enable ' + props.controlId + ' Condition', {
      expression: cdk.Fn.conditionEquals(enableParam, 'Available')
    });

    const ssmDocName = `ASR-${props.securityStandard}_${props.securityStandardVersion}_${props.controlId}`;
    const ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`;
    const ssmDocType = props.ssmDocFileName.substring(props.ssmDocFileName.length - 4).toLowerCase();

    const ssmDocIn = fs.readFileSync(ssmDocFQFileName, 'utf8');

    let ssmDocOut: string = '';
    const re = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/;

    for (const line of ssmDocIn.split('\n')) {
      const foundMatch = re.exec(line);
      if (foundMatch && foundMatch.groups && foundMatch.groups.script) {
        let pathAndFileToInsert = foundMatch.groups.script;
        // If a relative path is provided then use it
        if (pathAndFileToInsert.substring(0, 7) === 'common/') {
          pathAndFileToInsert = `${commonScripts}/${pathAndFileToInsert.substring(7)}`;
        } else {
          pathAndFileToInsert = `${scriptPath}/${pathAndFileToInsert}`;
        }
        const scriptIn = fs.readFileSync(pathAndFileToInsert, 'utf8');
        for (const scriptLine of scriptIn.split('\n')) {
          ssmDocOut += foundMatch.groups.padding + scriptLine + '\n';
        }
      } else {
        ssmDocOut += line + '\n';
      }
    }

    const ssmDoc = new CfnDocument(scope, `Control ${id}`, {
      name: ssmDocName,
      content: yaml.load(ssmDocOut),
      documentFormat: ssmDocType.toUpperCase(),
      documentType: 'Automation',
      updateMethod: 'NewVersion',
    });

    ssmDoc.cfnOptions.condition = installSsmDoc;

    return ssmDoc;
  }

  static createRemediationRunbook(scope: cdk.Construct, id: string, props: RemediationRunbookProps) {
    const ssmDocName = `ASR-${props.ssmDocName}`;
    let scriptPath = '';
    if (props.scriptPath == undefined) {
      scriptPath = 'ssmdocs/scripts';
    } else {
      scriptPath = props.scriptPath;
    }

    const ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`;
    const ssmDocType = props.ssmDocFileName.substring(props.ssmDocFileName.length - 4).toLowerCase();

    const ssmDocIn = fs.readFileSync(ssmDocFQFileName, 'utf8');

    let ssmDocOut: string = '';
    const re = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/;

    for (const line of ssmDocIn.split('\n')) {
      const foundMatch = re.exec(line);
      if (foundMatch && foundMatch.groups && foundMatch.groups.script) {
        const scriptIn = fs.readFileSync(`${scriptPath}/${foundMatch.groups.script}`, 'utf8');
        for (const scriptLine of scriptIn.split('\n')) {
          ssmDocOut += foundMatch.groups.padding + scriptLine + '\n';
        }
      } else {
        ssmDocOut += line + '\n';
      }
    }

    const runbook = new CfnDocument(scope, id, {
      content: yaml.load(ssmDocOut),
      documentFormat: ssmDocType.toUpperCase(),
      documentType: 'Automation',
      name: ssmDocName,
      updateMethod: 'NewVersion',
    });

    return runbook;
  }
};

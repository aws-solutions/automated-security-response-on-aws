// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  HardCodedString,
  BooleanVariable,
  NumberVariable,
  Output,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetIAMPasswordPolicyDocument(scope, id, {
    ...props,
    controlId: 'IAM.7',
    otherControlIds: ['IAM.11', 'IAM.12', 'IAM.13', 'IAM.14', 'IAM.15', 'IAM.16', 'IAM.17'],
  });
}

export class SetIAMPasswordPolicyDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const remediationName = 'SetIAMPasswordPolicy';

    super(scope, id, {
      ...props,
      securityControlId: 'IAM.7',
      remediationName,
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of(
        `Established a baseline password policy using the ${props.solutionAcronym}-${remediationName} runbook.`,
      ),
    });
  }
  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        AllowUsersToChangePassword: 'True',
        HardExpiry: 'True',
        MaxPasswordAge: '90',
        MinimumPasswordLength: '14',
        RequireSymbols: 'True',
        RequireNumbers: 'True',
        RequireUppercaseCharacters: 'True',
        RequireLowercaseCharacters: 'True',
        PasswordReusePrevention: '24',
      }),
    ];
  }

  /** @override */
  protected getInputParamsStepOutput(): Output[] {
    const AllowUsersToChangePasswordOutput: Output = {
      name: 'AllowUsersToChangePassword',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.AllowUsersToChangePassword',
    };
    const HardExpiryOutput: Output = {
      name: 'HardExpiry',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.HardExpiry',
    };
    const MaxPasswordAgeOutput: Output = {
      name: 'MaxPasswordAge',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.MaxPasswordAge',
    };
    const MinimumPasswordLengthOutput: Output = {
      name: 'MinimumPasswordLength',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.MinimumPasswordLength',
    };
    const RequireSymbolsOutput: Output = {
      name: 'RequireSymbols',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.RequireSymbols',
    };
    const RequireNumbersOutput: Output = {
      name: 'RequireNumbers',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.RequireNumbers',
    };
    const RequireUppercaseCharactersOutput: Output = {
      name: 'RequireUppercaseCharacters',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.RequireUppercaseCharacters',
    };
    const RequireLowercaseCharactersOutput: Output = {
      name: 'RequireLowercaseCharacters',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.RequireLowercaseCharacters',
    };
    const PasswordReusePreventionOutput: Output = {
      name: 'PasswordReusePrevention',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.PasswordReusePrevention',
    };

    const outputs: Output[] = [
      AllowUsersToChangePasswordOutput,
      HardExpiryOutput,
      MaxPasswordAgeOutput,
      MinimumPasswordLengthOutput,
      RequireSymbolsOutput,
      RequireNumbersOutput,
      RequireUppercaseCharactersOutput,
      RequireLowercaseCharactersOutput,
      PasswordReusePreventionOutput,
    ];

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.AllowUsersToChangePassword = BooleanVariable.of('GetInputParams.AllowUsersToChangePassword');
    params.HardExpiry = BooleanVariable.of('GetInputParams.HardExpiry');
    params.MaxPasswordAge = NumberVariable.of('GetInputParams.MaxPasswordAge');
    params.MinimumPasswordLength = NumberVariable.of('GetInputParams.MinimumPasswordLength');
    params.RequireSymbols = BooleanVariable.of('GetInputParams.RequireSymbols');
    params.RequireNumbers = BooleanVariable.of('GetInputParams.RequireNumbers');
    params.RequireUppercaseCharacters = BooleanVariable.of('GetInputParams.RequireUppercaseCharacters');
    params.RequireLowercaseCharacters = BooleanVariable.of('GetInputParams.RequireLowercaseCharacters');
    params.PasswordReusePrevention = NumberVariable.of('GetInputParams.PasswordReusePrevention');

    return params;
  }
}

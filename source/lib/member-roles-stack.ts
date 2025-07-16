// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { OrchestratorMemberRole } from './orchestrator_roles-construct';
import AdminAccountParam from './parameters/admin-account-param';
import NamespaceParam from './parameters/namespace-param';

export interface MemberRolesStackProps extends cdk.StackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
}

export class MemberRolesStack extends cdk.Stack {
  private readonly orchestratorMemberRole: OrchestratorMemberRole;
  private readonly namespace: NamespaceParam;

  constructor(scope: cdk.App, id: string, props: MemberRolesStackProps) {
    super(scope, id, props);
    /********************
     ** Parameters
     ********************/
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
    const adminRoleName = `${RESOURCE_PREFIX}-ASR-Orchestrator-Admin`;
    const adminAccount = new AdminAccountParam(this, 'AdminAccountParameter');
    this.namespace = new NamespaceParam(this, 'Namespace');
    this.orchestratorMemberRole = new OrchestratorMemberRole(this, 'OrchestratorMemberRole', {
      solutionId: props.solutionId,
      adminAccountId: adminAccount.value,
      adminRoleName: adminRoleName,
    });
  }
  getOrchestratorMemberRole(): OrchestratorMemberRole {
    return this.orchestratorMemberRole;
  }

  getNamespace(): string {
    return this.namespace.value;
  }
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { OrganizationPrincipal, PolicyStatement, Role } from 'aws-cdk-lib/aws-iam';
import { ArnFormat, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { OrgIdLookupConstruct } from './org-id-lookup';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { buildEventProcessorRoleNamePattern } from './cdk-helper/solution-resource-names';

interface ActionLogProps {
  logGroupName: string;
  resourceNamePrefix: string;
}

export class ActionLog extends Construct {
  constructor(scope: Construct, id: string, props: ActionLogProps) {
    super(scope, id);
    const stack = Stack.of(this);
    const orgIdLookup = new OrgIdLookupConstruct(this, 'OrgIdLookup');

    // target LogGroup for ASR events. EventProcessor lambdas in member accounts will write filtered CloudTrail event here.
    const logGroup = new LogGroup(scope, 'CloudTrailEventsLogGroup', {
      logGroupName: props.logGroupName,
      retention: RetentionDays.TEN_YEARS,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    addCfnGuardSuppression(logGroup, 'CLOUDWATCH_LOG_GROUP_ENCRYPTED');

    // The source identity must be the caller's own account, and the permission policy below only
    // allows streams prefixed with it, so no member can write entries under another account.
    const memberEventProcessorPrincipal = new OrganizationPrincipal(orgIdLookup.organizationId).withConditions({
      StringEquals: {
        'sts:SourceIdentity': '${aws:PrincipalAccount}',
      },
      ArnLike: {
        'aws:PrincipalArn': `arn:${stack.partition}:iam::*:role/${buildEventProcessorRoleNamePattern(props.resourceNamePrefix)}`,
      },
    });

    // role for the EventProcessor lambda from the members to assume for cross-account write access to the LogGroup
    const crossAccountRole = new Role(this, 'CrossAccountLogWriterRole', {
      roleName: 'CrossAccountLogWriterRole',
      description: 'Lets member account EventProcessor functions write their own entries to the ASR Action Log',
      assumedBy: memberEventProcessorPrincipal,
    });
    crossAccountRole.assumeRolePolicy?.addStatements(
      new PolicyStatement({
        actions: ['sts:SetSourceIdentity'],
        principals: [memberEventProcessorPrincipal],
      }),
    );
    crossAccountRole.addToPolicy(
      new PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [
          stack.formatArn({
            service: 'logs',
            resource: 'log-group',
            resourceName: `${props.logGroupName}:log-stream:\${aws:SourceIdentity}-*`,
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          }),
        ],
      }),
    );

    addCfnGuardSuppression(crossAccountRole, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
  }
}

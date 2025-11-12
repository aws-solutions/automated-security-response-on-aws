// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { OrganizationPrincipal, PolicyStatement, Role } from 'aws-cdk-lib/aws-iam';
import { RemovalPolicy } from 'aws-cdk-lib';
import { OrgIdLookupConstruct } from './org-id-lookup';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { CrossAccount } from './constants/parameters';

interface ActionLogProps {
  logGroupName: string;
}

export class ActionLog extends Construct {
  constructor(scope: Construct, id: string, props: ActionLogProps) {
    super(scope, id);
    const orgIdLookup = new OrgIdLookupConstruct(this, 'OrgIdLookup');

    // target LogGroup for ASR events. EventProcessor lambdas in member accounts will write filtered CloudTrail event here.
    const logGroup = new LogGroup(scope, 'CloudTrailEventsLogGroup', {
      logGroupName: props.logGroupName,
      retention: RetentionDays.TEN_YEARS,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    addCfnGuardSuppression(logGroup, 'CLOUDWATCH_LOG_GROUP_ENCRYPTED');

    // role for the EventProcessor lambda from the members to assume for cross-account write access to the LogGroup
    const crossAccountRole = new Role(this, 'CrossAccountLogWriterRole', {
      roleName: 'CrossAccountLogWriterRole',
      description: 'Role for cross-account access to write to CloudWatch Logs with External ID security',
      assumedBy: new OrganizationPrincipal(orgIdLookup.organizationId).withConditions({
        StringEquals: {
          'sts:ExternalId': CrossAccount.FIXED_EXTERNAL_ID,
        },
      }),
    });
    crossAccountRole.addToPolicy(
      new PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents', 'logs:DescribeLogStreams'],
        resources: [
          logGroup.logGroupArn,
          `${logGroup.logGroupArn}:*`, // Allow access to all log streams in this group
        ],
      }),
    );
    logGroup.grantWrite(crossAccountRole);

    addCfnGuardSuppression(crossAccountRole, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
  }
}

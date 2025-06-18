// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack } from 'aws-cdk-lib';
import { AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Alias, Key } from 'aws-cdk-lib/aws-kms';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import overrideLogicalId from '../cdk-helper/override-logical-id';

export interface MemberRemediationKeyProps {
  readonly solutionId: string;
}

export class MemberRemediationKey extends Construct {
  constructor(scope: Construct, id: string, props: MemberRemediationKeyProps) {
    super(scope, id);

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    const stack = Stack.of(this);

    const kmsKeyPolicy = new PolicyDocument();
    const kmsPerms = new PolicyStatement();
    kmsPerms.addActions(
      'kms:GenerateDataKey',
      'kms:GenerateDataKeyPair',
      'kms:GenerateDataKeyPairWithoutPlaintext',
      'kms:GenerateDataKeyWithoutPlaintext',
      'kms:Decrypt',
      'kms:Encrypt',
      'kms:ReEncryptFrom',
      'kms:ReEncryptTo',
      'kms:DescribeKey',
      'kms:DescribeCustomKeyStores',
    );
    kmsPerms.effect = Effect.ALLOW;
    kmsPerms.addResources('*'); // Only the key the policydocument is attached to
    kmsPerms.addPrincipals(new ServicePrincipal('sns.amazonaws.com'));
    kmsPerms.addPrincipals(new ServicePrincipal('s3.amazonaws.com'));
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.region}.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal(`cloudtrail.${stack.urlSuffix}`));
    kmsPerms.addPrincipals(new ServicePrincipal('cloudwatch.amazonaws.com'));
    kmsKeyPolicy.addStatements(kmsPerms);

    const kmsRootPolicy = new PolicyStatement({
      principals: [new AccountRootPrincipal()],
      actions: ['kms:*'],
      resources: ['*'],
    });
    kmsKeyPolicy.addStatements(kmsRootPolicy);

    const kmsKey: Key = new Key(scope, 'SHARR Remediation Key', {
      enableKeyRotation: true,
      policy: kmsKeyPolicy,
    });

    const alias = new Alias(scope, 'SHARR Remediation Key Alias', {
      aliasName: `${props.solutionId}-SHARR-Remediation-Key`,
      targetKey: kmsKey,
    });
    overrideLogicalId(alias, 'SHARRRemediationKeyAlias5531874D');

    new StringParameter(scope, 'SHARR Key Alias', {
      description: 'KMS Customer Managed Key that will encrypt data for remediations',
      parameterName: `/Solutions/${props.solutionId}/CMK_REMEDIATION_ARN`,
      stringValue: kmsKey.keyArn,
    });
  }
}

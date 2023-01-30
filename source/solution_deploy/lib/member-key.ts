// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack } from 'aws-cdk-lib';
import { AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Alias, CfnAlias, CfnKey, Key } from 'aws-cdk-lib/aws-kms';
import { CfnParameter as CfnSsmParameter, StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface MemberKeyProps {
  readonly solutionId: string;
}

export class MemberKey extends Construct {
  constructor(scope: Construct, id: string, props: MemberKeyProps) {
    super(scope, id);

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
      'kms:DescribeCustomKeyStores'
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

    const kmsKey: Key = new Key(this, 'SHARR Remediation Key', {
      enableKeyRotation: true,
      policy: kmsKeyPolicy,
    });
    (kmsKey.node.defaultChild as CfnKey).overrideLogicalId('SHARRRemediationKeyE744743D');

    const alias = new Alias(this, 'SHARR Remediation Key Alias', {
      aliasName: `${props.solutionId}-SHARR-Remediation-Key`,
      targetKey: kmsKey,
    });
    (alias.node.defaultChild as CfnAlias).overrideLogicalId('SHARRRemediationKeyAlias5531874D');

    const ssmParam = new StringParameter(this, 'SHARR Key Alias', {
      description: 'KMS Customer Managed Key that will encrypt data for remediations',
      parameterName: `/Solutions/${props.solutionId}/CMK_REMEDIATION_ARN`,
      stringValue: kmsKey.keyArn,
    });
    (ssmParam.node.defaultChild as CfnSsmParameter).overrideLogicalId('SHARRKeyAliasEBF509D8');
  }
}

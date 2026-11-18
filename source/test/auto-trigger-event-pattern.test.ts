// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import {
  MULTI_SERVICE_REMEDIATION_IDS,
  MULTI_SERVICE_REMEDIATION_SOURCES,
  REMEDIATION_SUPPORTED_RESOURCE_TYPES,
  normalizeResourceTypeToAsff,
} from '@asr/data-models';
import { Trigger, autoTriggerResourceTypes } from '../lib/ssmplaybook';

const EVENT_PATTERN_MAX_CHARACTERS = 2048;

interface AutoTriggerBranch {
  ProductArn?: { suffix?: string; 'anything-but'?: { suffix: string[] } }[];
  Resources?: { Type: string[] };
}

interface AutoTriggerEventPattern {
  detail: { findings: { $or: AutoTriggerBranch[] } };
}

function synthesizeAutoTriggerEventPattern(): AutoTriggerEventPattern {
  const app = new App();
  const stack = new Stack(app, 'AutoTriggerTestStack');
  new Trigger(stack, 'FindingEventsTrigger', {
    targetArn: 'arn:aws:sqs:us-east-1:111111111111:pre-processor-queue',
    solutionTMN: 'automated-security-response-on-aws',
    solutionId: 'SO0111',
  });
  const rules = Template.fromStack(stack).findResources('AWS::Events::Rule');
  const [rule] = Object.values(rules);
  return rule.Properties.EventPattern;
}

function securityHubProductArnPrefix(): { prefix: { 'Fn::Join': unknown[] } } {
  return { prefix: { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':securityhub']] } };
}

test('AutoTrigger admits only the finding shapes and resource types the Pre-Processor can remediate', () => {
  // ARRANGE / ACT
  const branches = synthesizeAutoTriggerEventPattern().detail.findings.$or;

  // ASSERT
  expect(branches).toEqual([
    {
      SchemaVersion: ['2018-10-08'],
      ProductArn: [
        {
          'anything-but': {
            suffix: [
              '::product/aws/access-analyzer',
              '::product/aws/inspector',
              '::product/aws/guardduty',
              '::product/aws/macie',
            ],
          },
        },
      ],
    },
    {
      SchemaVersion: ['2018-10-08'],
      ProductArn: [{ suffix: '::product/aws/access-analyzer' }],
      Resources: { Type: ['AwsS3Bucket', 'AWS::S3::Bucket', 'AwsKmsKey', 'AWS::KMS::Key'] },
    },
    {
      SchemaVersion: ['2018-10-08'],
      ProductArn: [{ suffix: '::product/aws/inspector' }],
      Resources: { Type: ['AwsEc2Instance', 'AWS::EC2::Instance'] },
    },
    {
      SchemaVersion: ['2018-10-08'],
      ProductArn: [{ suffix: '::product/aws/guardduty' }],
      Resources: { Type: ['AwsIamAccessKey', 'AWS::IAM::AccessKey'] },
    },
    {
      SchemaVersion: ['2018-10-08'],
      ProductArn: [{ suffix: '::product/aws/macie' }],
      Resources: { Type: ['AwsS3Object', 'AWS::S3::Object'] },
    },
    {
      class_name: ['Compliance Finding'],
      class_uid: [2003],
      compliance: { control: [{ exists: true }] },
      metadata: { product: { uid: [securityHubProductArnPrefix()] } },
    },
    {
      class_name: ['Vulnerability Finding'],
      class_uid: [2002],
      metadata: { product: { name: ['Inspector'] } },
      resources: { type: ['AwsEc2Instance', 'AWS::EC2::Instance'] },
    },
    {
      class_name: ['Detection Finding'],
      class_uid: [2004],
      metadata: { product: { name: ['GuardDuty'] } },
      resources: { type: ['AwsIamAccessKey', 'AWS::IAM::AccessKey'] },
    },
    {
      class_name: ['Detection Finding', 'Data Security Finding'],
      class_uid: [2004, 2006],
      metadata: { product: { name: ['Macie'] } },
      resources: { type: ['AwsS3Object', 'AWS::S3::Object'] },
    },
  ]);
});

test.each(Object.entries(REMEDIATION_SUPPORTED_RESOURCE_TYPES))(
  'AutoTrigger resource types for %s are its supported types in ASFF and OCSF form',
  (remediationId, supportedAsffTypes) => {
    // ACT
    const types = autoTriggerResourceTypes([remediationId]);

    // ASSERT
    expect(new Set(types.map(normalizeResourceTypeToAsff))).toEqual(new Set(supportedAsffTypes));
    for (const asffType of supportedAsffTypes) {
      expect(types).toContain(asffType);
      expect(types.some((type) => type.includes('::') && normalizeResourceTypeToAsff(type) === asffType)).toBe(true);
    }
  },
);

test('AutoTrigger resource types reject a remediation without a supported resource type list', () => {
  expect(() => autoTriggerResourceTypes(['S3.1'])).toThrow('No supported resource types defined for S3.1');
});

test('AutoTrigger resource types fail when a supported resource type has no OCSF form', async () => {
  // ARRANGE: a new remediation whose resource type was not added to the OCSF form table
  const actual = jest.requireActual('@asr/data-models');
  jest.doMock('@asr/data-models', () => ({
    ...actual,
    REMEDIATION_SUPPORTED_RESOURCE_TYPES: {
      ...actual.REMEDIATION_SUPPORTED_RESOURCE_TYPES,
      'Inspector.LambdaVulnerability': ['AwsLambdaFunction'],
    },
  }));

  try {
    await jest.isolateModulesAsync(async () => {
      const { autoTriggerResourceTypes: isolatedAutoTriggerResourceTypes } = await import('../lib/ssmplaybook');

      // ACT / ASSERT
      expect(() => isolatedAutoTriggerResourceTypes(['Inspector.LambdaVulnerability'])).toThrow(
        'No OCSF form defined for resource type AwsLambdaFunction',
      );
    });
  } finally {
    jest.dontMock('@asr/data-models');
  }
});

test('AutoTrigger resource types of several remediations are their union without duplicates', () => {
  expect(autoTriggerResourceTypes(['Inspector.InstanceVulnerability', 'GuardDuty.IAMUser'])).toEqual([
    'AwsEc2Instance',
    'AWS::EC2::Instance',
    'AwsIamAccessKey',
    'AWS::IAM::AccessKey',
  ]);
  expect(autoTriggerResourceTypes(['GuardDuty.IAMUser', 'GuardDuty.IAMUser'])).toEqual([
    'AwsIamAccessKey',
    'AWS::IAM::AccessKey',
  ]);
});

describe('AutoTrigger rule agrees with the multi-service remediation definitions', () => {
  const branches = (): AutoTriggerBranch[] => synthesizeAutoTriggerEventPattern().detail.findings.$or;

  test('every multi-service remediation has a source and supported resource types, and nothing else does', () => {
    const ids = [...MULTI_SERVICE_REMEDIATION_IDS].sort();
    expect(Object.keys(MULTI_SERVICE_REMEDIATION_SOURCES).sort()).toEqual(ids);
    expect(Object.keys(REMEDIATION_SUPPORTED_RESOURCE_TYPES).sort()).toEqual(ids);
  });

  test.each(Object.entries(MULTI_SERVICE_REMEDIATION_SOURCES))(
    'the ASFF branch for %s admits every one of its supported resource types and only those of its product',
    (remediationId, { productArnService }) => {
      const productBranches = branches().filter((branch) =>
        branch.ProductArn?.some((matcher) => matcher.suffix === `::product/aws/${productArnService}`),
      );
      expect(productBranches).toHaveLength(1);

      const admitted = new Set<string>(productBranches[0].Resources?.Type);
      for (const asffType of REMEDIATION_SUPPORTED_RESOURCE_TYPES[remediationId]) {
        expect(admitted).toContain(asffType);
      }
      const sameProductIds = Object.entries(MULTI_SERVICE_REMEDIATION_SOURCES)
        .filter(([, source]) => source.productArnService === productArnService)
        .map(([id]) => id);
      const expected = new Set(sameProductIds.flatMap((id) => REMEDIATION_SUPPORTED_RESOURCE_TYPES[id]));
      expect(new Set([...admitted].map(normalizeResourceTypeToAsff))).toEqual(expected);
    },
  );

  test('the general ASFF branch excludes exactly the product slugs of the multi-service remediations', () => {
    const slugs = new Set(Object.values(MULTI_SERVICE_REMEDIATION_SOURCES).map((source) => source.productArnService));
    const excluded = branches().flatMap((branch) => branch.ProductArn?.[0]?.['anything-but']?.suffix ?? []);
    expect(new Set(excluded)).toEqual(new Set([...slugs].map((slug) => `::product/aws/${slug}`)));
  });
});

test('AutoTrigger event pattern fits the EventBridge pattern size quota in every partition', () => {
  const pattern = JSON.stringify(synthesizeAutoTriggerEventPattern()).replace(
    /\{"Fn::Join":\["",\["arn:",\{"Ref":"AWS::Partition"\},":securityhub"\]\]\}/g,
    '"arn:aws-us-gov:securityhub"',
  );

  // ASSERT
  expect(pattern).not.toContain('Fn::');
  expect(pattern.length).toBeLessThanOrEqual(EVENT_PATTERN_MAX_CHARACTERS);
});

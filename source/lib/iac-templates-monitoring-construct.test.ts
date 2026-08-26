// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, CfnCondition, DefaultStackSynthesizer, Fn, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Effect, PolicyStatement, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { IaCTemplatesMonitoringConstruct } from './iac-templates-monitoring-construct';

function buildStack(): Stack {
  const app = new App();
  const stack = new Stack(app, 'TestStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });

  const key = new Key(stack, 'Key');
  const topic = new Topic(stack, 'Topic', { masterKey: key });
  // Force CDK to lazily create the topic resource policy (id 'Policy') so the
  // construct can find and gate it. Mirrors what SnsDestination would do.
  topic.addToResourcePolicy(
    new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['sns:Publish'],
      resources: [topic.topicArn],
      principals: [new ServicePrincipal('s3.amazonaws.com')],
    }),
  );

  const condition = new CfnCondition(stack, 'AlarmsEnabled', { expression: Fn.conditionEquals('yes', 'yes') });
  const bucket = new Bucket(stack, 'TemplatesBucket');
  new IaCTemplatesMonitoringConstruct(stack, 'Monitoring', {
    bucket,
    bucketSourceArn: 'arn:aws:s3:::so0111-asr-iac-templates-test',
    topic,
    topicEncryptionKey: key,
    topicCondition: condition,
  });

  return stack;
}

describe('IaCTemplatesMonitoringConstruct', () => {
  describe('GIVEN a normally-constructed stack', () => {
    let template: Template;
    beforeAll(() => {
      template = Template.fromStack(buildStack());
    });

    it('THEN the per-bucket Custom::S3BucketNotifications is gated on the topic condition', () => {
      template.hasResource('Custom::S3BucketNotifications', { Condition: 'AlarmsEnabled' });
    });

    it('THEN the singleton BucketNotificationsHandler Lambda is gated on the topic condition', () => {
      const lambdas = template.findResources('AWS::Lambda::Function', {
        Condition: 'AlarmsEnabled',
      });
      const ids = Object.keys(lambdas).filter((id) => id.includes('BucketNotificationsHandler'));
      expect(ids).toHaveLength(1);
    });

    it('THEN the singleton handler IAM Role is gated on the topic condition', () => {
      const roles = template.findResources('AWS::IAM::Role', { Condition: 'AlarmsEnabled' });
      const ids = Object.keys(roles).filter((id) => id.includes('BucketNotificationsHandler'));
      expect(ids).toHaveLength(1);
    });

    it('THEN the per-bucket handler policy grants s3:PutBucketNotification on the IaC bucket', () => {
      const policies = template.findResources('AWS::IAM::Policy');
      const handlerPolicies = Object.entries(policies).filter(
        ([id]) => id.includes('NotificationsHandlerPolicy') || id.includes('RoleDefaultPolicy'),
      );
      expect(handlerPolicies.length).toBeGreaterThanOrEqual(1);
      const hasPutNotification = handlerPolicies.some(([, policy]) => {
        const statements = (policy as any).Properties?.PolicyDocument?.Statement ?? [];
        return statements.some((s: any) => s.Action === 's3:PutBucketNotification');
      });
      expect(hasPutNotification).toBe(true);
    });

    it('THEN the topic resource policy is gated on the topic condition', () => {
      template.hasResource('AWS::SNS::TopicPolicy', { Condition: 'AlarmsEnabled' });
    });

    it('THEN the singleton handler Lambda has the expected cfn-guard suppressions', () => {
      const matches = template.findResources('AWS::Lambda::Function', {
        Metadata: {
          guard: {
            SuppressedRules: Match.arrayWith([
              'CFN_NO_EXPLICIT_RESOURCE_NAMES',
              'LAMBDA_CONCURRENCY_CHECK',
              'LAMBDA_INSIDE_VPC',
            ]),
          },
        },
      });
      const handlerIds = Object.keys(matches).filter((id) => id.includes('BucketNotificationsHandler'));
      expect(handlerIds).toHaveLength(1);
    });

    it('THEN the bucket gets an OBJECT_REMOVED notification to the topic', () => {
      template.hasResourceProperties('Custom::S3BucketNotifications', {
        NotificationConfiguration: {
          TopicConfigurations: Match.arrayWith([Match.objectLike({ Events: ['s3:ObjectRemoved:*'] })]),
        },
      });
    });

    it('THEN the KMS key policy grants S3 GenerateDataKey*/Decrypt scoped to the bucket ARN', () => {
      template.hasResourceProperties('AWS::KMS::Key', {
        KeyPolicy: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['kms:GenerateDataKey*', 'kms:Decrypt'],
              Principal: { Service: 's3.amazonaws.com' },
              Condition: {
                ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::so0111-asr-iac-templates-test' },
              },
            }),
          ]),
        },
      });
    });
  });

  describe('GIVEN no addEventNotification has been called for any bucket in the stack', () => {
    it('THEN the construct throws because the BucketNotificationsHandler singleton is missing', () => {
      const app = new App();
      const stack = new Stack(app, 'TestStack', {
        synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      });
      const key = new Key(stack, 'Key');
      const topic = new Topic(stack, 'Topic', { masterKey: key });
      const condition = new CfnCondition(stack, 'AlarmsEnabled', { expression: Fn.conditionEquals('yes', 'yes') });
      // Use a bucket that has no event notifications wired up via addEventNotification —
      // we wire it inside the construct, but only AFTER we'd want to find an existing
      // singleton. To force the singleton to be missing we directly stub addEventNotification.
      const bucket = new Bucket(stack, 'TemplatesBucket');
      bucket.addEventNotification = () => {
        // intentionally a no-op so neither the singleton nor the per-bucket
        // Notifications resource gets created
      };

      expect(() => {
        new IaCTemplatesMonitoringConstruct(stack, 'Monitoring', {
          bucket,
          bucketSourceArn: 'arn:aws:s3:::so0111-asr-iac-templates-test',
          topic,
          topicEncryptionKey: key,
          topicCondition: condition,
        });
      }).toThrow(/BucketNotificationsHandler/);
    });
  });
});

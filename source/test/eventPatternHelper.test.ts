// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { Stack } from 'aws-cdk-lib';
import { EventPatternHelper } from '../lib/cdk-helper/eventeattern-helper';
import { EventPattern } from 'aws-cdk-lib/aws-events';

describe('EventPatternHelper', () => {
  let stack: Stack;
  let props: any;

  beforeEach(() => {
    stack = new Stack();
    props = {
      generatorId: 'test-generator-id',
      targetAccountIDs: new cdk.CfnParameter(stack, 'TargetAccountIDs', {
        type: 'String',
        default: '111111111111,222222222222',
      }),
      isAllInclude: new cdk.CfnCondition(stack, 'IsAllInclude', {
        expression: cdk.Fn.conditionEquals('true', 'true'),
      }),
      isAllExclude: new cdk.CfnCondition(stack, 'IsAllExclude', {
        expression: cdk.Fn.conditionEquals('false', 'true'),
      }),
      isInclude: new cdk.CfnCondition(stack, 'IsInclude', {
        expression: cdk.Fn.conditionEquals('true', 'true'),
      }),
    };
  });

  describe('Static Properties', () => {
    it('should have correct constant values', () => {
      expect(EventPatternHelper.WORKFLOW_STATUS).toEqual({ Status: ['NEW'] });
      expect(EventPatternHelper.COMPLIANCE_STATUS).toEqual({ Status: ['FAILED', 'WARNING'] });
      expect(EventPatternHelper.RECORD_STATE).toEqual(['ACTIVE']);
    });

    it('should calculate correct pattern max length', () => {
      const maxLength = EventPatternHelper.getPatternMaxLength();
      expect(maxLength).toBeLessThanOrEqual(4096);
      expect(maxLength).toBeGreaterThan(0);
    });
  });

  describe('Pattern Generation', () => {
    it('should create base pattern correctly', () => {
      const helper = new EventPatternHelper(props);
      const pattern: EventPattern = helper.createEventPattern();

      expect(pattern.source).toEqual(['aws.securityhub']);
      expect(pattern.detailType).toEqual(['Security Hub Findings - Imported']);
      if (pattern.detail && typeof pattern.detail === 'object' && 'findings' in pattern.detail) {
        expect(pattern.detail.findings.Workflow).toEqual(EventPatternHelper.WORKFLOW_STATUS);
        expect(pattern.detail.findings.Compliance).toEqual(EventPatternHelper.COMPLIANCE_STATUS);
        expect(pattern.detail.findings.RecordState).toEqual(EventPatternHelper.RECORD_STATE);
      }
    });

    it('should include generator ID in pattern', () => {
      const helper = new EventPatternHelper(props);
      const pattern = helper.createEventPattern();
      if (pattern.detail && typeof pattern.detail === 'object' && 'findings' in pattern.detail) {
        expect(pattern.detail.findings.GeneratorId).toEqual([props.generatorId]);
      }
    });
  });

  describe('Pattern Length Calculations', () => {
    it('should calculate pattern length correctly', () => {
      const testPattern = { test: 'value' };
      const length = EventPatternHelper.getPatternLength(testPattern);
      expect(length).toBe(JSON.stringify(testPattern).length);
    });

    it('should not exceed maximum pattern length', () => {
      const helper = new EventPatternHelper(props);
      const pattern = helper.createEventPattern();
      const patternLength = EventPatternHelper.getPatternLength(pattern);

      expect(patternLength).toBeLessThanOrEqual(4096);
    });
  });
});

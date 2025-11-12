// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getSecurityHubConsoleUrl, getStepFunctionsConsoleUrl } from '../findingUtils';

describe('findingUtils console URL functions', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('getSecurityHubConsoleUrl', () => {
    it('should generate correct URL for AWS commercial partition', () => {
      process.env.AWS_REGION = 'us-east-1';
      process.env.AWS_PARTITION = 'aws';

      const findingId = 'arn:aws:securityhub:us-east-1:123456789012:finding/test-finding';
      const url = getSecurityHubConsoleUrl(findingId);

      expect(url).toContain('https://us-east-1.console.aws.amazon.com');
      expect(url).toContain(encodeURIComponent(findingId));
    });

    it('should generate correct URL for AWS GovCloud partition', () => {
      const findingId = 'test-finding-id';
      const url = getSecurityHubConsoleUrl(findingId, 'us-gov-west-1', 'aws-us-gov');

      expect(url).toContain('https://us-gov-west-1.console.amazonaws-us-gov.com');
      expect(url).toContain('us-gov-west-1');
    });

    it('should use custom URL pattern from environment variable', () => {
      process.env.CONSOLE_URL_PATTERN = '/custom/path?finding=${encodeURIComponent(findingId)}';

      const findingId = 'test-finding';
      const url = getSecurityHubConsoleUrl(findingId, 'us-west-2');

      expect(url).toContain('/custom/path?finding=');
    });

    it('should generate Security Hub v2 URL when SECURITY_HUB_V2_ENABLED is true', () => {
      process.env.SECURITY_HUB_V2_ENABLED = 'true';
      process.env.AWS_REGION = 'us-east-1';
      process.env.AWS_PARTITION = 'aws';

      const findingId =
        'arn:aws:securityhub:us-east-1:242201278079:security-control/CloudWatch.17/finding/7ee5b313-debb-4bbd-a356-fb7474897e17';
      const url = getSecurityHubConsoleUrl(findingId);

      expect(url).toContain('https://us-east-1.console.aws.amazon.com');
      expect(url).toContain('/securityhub/v2/home');
      expect(url).toContain('finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253A');
      expect(url).toContain(encodeURIComponent(findingId));
    });

    it('should generate Security Hub v1 URL when SECURITY_HUB_V2_ENABLED is false', () => {
      process.env.SECURITY_HUB_V2_ENABLED = 'false';
      process.env.AWS_REGION = 'us-east-1';
      process.env.AWS_PARTITION = 'aws';

      const findingId = 'arn:aws:securityhub:us-east-1:123456789012:finding/test-finding';
      const url = getSecurityHubConsoleUrl(findingId);

      expect(url).toContain('https://us-east-1.console.aws.amazon.com');
      expect(url).toContain('/securityhub/home');
      expect(url).toContain('Id%3D%255Coperator%255C%253AEQUALS%255C%253A');
      expect(url).toContain(encodeURIComponent(findingId));
    });
  });

  it('should generate Security Hub v2 URL for GovCloud when SECURITY_HUB_V2_ENABLED is true', () => {
    process.env.SECURITY_HUB_V2_ENABLED = 'true';

    const findingId =
      'arn:aws-us-gov:securityhub:us-gov-west-1:123456789012:security-control/S3.1/finding/test-finding';
    const url = getSecurityHubConsoleUrl(findingId, 'us-gov-west-1', 'aws-us-gov');

    expect(url).toContain('https://us-gov-west-1.console.amazonaws-us-gov.com');
    expect(url).toContain('/securityhub/v2/home');
    expect(url).toContain('finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253A');
  });

  describe('getStepFunctionsConsoleUrl', () => {
    it('should generate correct URL for Step Functions execution', () => {
      process.env.AWS_REGION = 'us-east-1';

      const executionId = 'arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:execution-id';
      const url = getStepFunctionsConsoleUrl(executionId, 'us-east-1');

      expect(url).toContain('https://us-east-1.console.aws.amazon.com');
      expect(url).toContain('/states/home');
      expect(url).toContain(encodeURIComponent(executionId));
    });

    it('should generate correct URL for AWS GovCloud partition', () => {
      const executionId = 'test-execution-id';
      const url = getStepFunctionsConsoleUrl(executionId, 'us-gov-west-1', 'aws-us-gov');

      expect(url).toContain('https://us-gov-west-1.console.amazonaws-us-gov.com');
    });

    it('should use custom execution URL pattern from environment variable', () => {
      process.env.EXECUTION_CONSOLE_URL_PATTERN = '/custom/executions/executionId';

      const executionId = 'test-execution';
      const url = getStepFunctionsConsoleUrl(executionId, 'us-west-2');

      expect(url).toContain('/custom/executions/executionId');
    });
  });
});

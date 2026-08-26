// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  controlIdToFindingType,
  getControlIdFromFindingId,
  getSecurityHubConsoleUrl,
  getStepFunctionsConsoleUrl,
  partitionFindingIdsByKeyDerivability,
  resolveControlId,
  toDbFindingId,
  tryFindingKeyFromFindingId,
  tryResolveControlId,
  UnresolvableControlIdError,
} from '../findingUtils';
import type { FindingId } from '@asr/data-models';

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

describe('toDbFindingId', () => {
  it('sanitizes a consolidated finding ARN', () => {
    const result = toDbFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc');
    expect(result).toBe('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc');
  });

  it('returns undefined for non-ARN input', () => {
    expect(toDbFindingId('not-an-arn')).toBeUndefined();
  });

  it('strips control characters from finding ARN', () => {
    const result = toDbFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc\x00');
    expect(result).not.toContain('\x00');
  });
});

describe('getControlIdFromFindingId', () => {
  it('extracts control id from a consolidated Security Hub ARN', () => {
    const result = getControlIdFromFindingId(
      'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc',
    );
    expect(result).toBe('security-control/S3.1');
  });

  it('extracts control id from an unconsolidated Security Hub ARN', () => {
    const result = getControlIdFromFindingId(
      'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/abc',
    );
    expect(result).toBe('aws-foundational-security-best-practices/v/1.0.0/S3.1');
  });

  it('returns the multi-service remediation id for a GuardDuty native ARN', () => {
    const result = getControlIdFromFindingId(
      'arn:aws:guardduty:us-east-1:123456789012:detector/abcd1234efgh5678/finding/9876543210',
    );
    expect(result).toBe('GuardDuty.IAMUser');
  });

  it('returns the multi-service remediation id for an Inspector native ARN', () => {
    const result = getControlIdFromFindingId(
      'arn:aws:inspector2:us-east-1:123456789012:finding/abc123def456ghi789jkl012mno345pqr',
    );
    expect(result).toBe('Inspector.InstanceVulnerability');
  });

  it('returns the multi-service remediation id for a Macie native ARN', () => {
    const result = getControlIdFromFindingId('arn:aws:macie2:us-east-1:123456789012:finding/abc-def-ghi');
    expect(result).toBe('Macie.SensitiveDataS3Object');
  });

  it('returns the multi-service remediation id for an IAM Access Analyzer native ARN', () => {
    // Real IAA findings reach the PreProcessor without a Compliance block, so
    // the controlId must be derivable from the finding ARN alone.
    const result = getControlIdFromFindingId(
      'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer/arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000',
    );
    expect(result).toBe('IAMAccessAnalyzer.ExternalAccess');
  });

  it('recognizes native ARNs across AWS partitions (aws-cn, aws-us-gov)', () => {
    expect(getControlIdFromFindingId('arn:aws-cn:guardduty:cn-north-1:123456789012:detector/abc/finding/def')).toBe(
      'GuardDuty.IAMUser',
    );
    expect(getControlIdFromFindingId('arn:aws-us-gov:macie2:us-gov-west-1:123456789012:finding/abc-def')).toBe(
      'Macie.SensitiveDataS3Object',
    );
    expect(
      getControlIdFromFindingId(
        'arn:aws-us-gov:access-analyzer:us-gov-west-1:123456789012:analyzer/test/arn:aws-us-gov:s3:::bucket',
      ),
    ).toBe('IAMAccessAnalyzer.ExternalAccess');
  });

  it('returns undefined for a non-ARN string', () => {
    expect(getControlIdFromFindingId('not-an-arn')).toBeUndefined();
  });

  it('returns undefined for an unrecognized AWS service ARN', () => {
    expect(getControlIdFromFindingId('arn:aws:s3:::some-bucket')).toBeUndefined();
  });
});

describe('controlIdToFindingType', () => {
  it('prefixes a bare Security Hub security control id with security-control/', () => {
    // ARRANGE / ACT / ASSERT
    expect(controlIdToFindingType('S3.5')).toBe('security-control/S3.5');
    expect(controlIdToFindingType('EC2.2')).toBe('security-control/EC2.2');
    expect(controlIdToFindingType('CIS.1.1')).toBe('security-control/CIS.1.1');
  });

  it('passes through multi-service remediation ids unchanged', () => {
    // ARRANGE / ACT / ASSERT
    expect(controlIdToFindingType('Inspector.InstanceVulnerability')).toBe('Inspector.InstanceVulnerability');
    expect(controlIdToFindingType('GuardDuty.IAMUser')).toBe('GuardDuty.IAMUser');
    expect(controlIdToFindingType('Macie.SensitiveDataS3Object')).toBe('Macie.SensitiveDataS3Object');
  });

  it('passes through values already in partition form (containing a slash)', () => {
    // ARRANGE / ACT / ASSERT
    expect(controlIdToFindingType('security-control/S3.5')).toBe('security-control/S3.5');
    expect(controlIdToFindingType('aws-foundational-security-best-practices/v/1.0.0/S3.5')).toBe(
      'aws-foundational-security-best-practices/v/1.0.0/S3.5',
    );
  });

  it('sanitizes the control id before mapping', () => {
    // ARRANGE / ACT — embedded control character is stripped, then prefixed.
    const result = controlIdToFindingType('S3.5\u0000');

    // ASSERT
    expect(result).toBe('security-control/S3.5');
  });
});

describe('tryResolveControlId', () => {
  const CONSOLIDATED_ARN = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc';
  const UNCONSOLIDATED_ARN =
    'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/abc';
  const MACIE_BARE_HASH_ID = '9f8e7d6c5b4a39281706';

  it('returns the prefixed value for a consolidated ARN', () => {
    // ARRANGE / ACT
    const result = tryResolveControlId({ Id: CONSOLIDATED_ARN, Compliance: { SecurityControlId: 'S3.1' } });

    // ASSERT — the ARN wins over Compliance, and the prefixed form is returned
    expect(result).toBe('security-control/S3.1');
  });

  it('keeps the standard prefix for an unconsolidated ARN', () => {
    // ARRANGE / ACT
    const result = tryResolveControlId({ Id: UNCONSOLIDATED_ARN, Compliance: { SecurityControlId: 'S3.1' } });

    // ASSERT — the standard and version must survive, since the partition key carries them
    expect(result).toBe('aws-foundational-security-best-practices/v/1.0.0/S3.1');
  });

  it('maps a native multi-service ARN to its remediation id', () => {
    // ARRANGE / ACT
    const result = tryResolveControlId({
      Id: 'arn:aws:macie2:us-east-1:123456789012:finding/abc',
      Compliance: { SecurityControlId: 'Macie.SensitiveDataS3Object' },
    });

    // ASSERT
    expect(result).toBe('Macie.SensitiveDataS3Object');
  });

  it('falls back to Compliance.SecurityControlId for a non-ARN id', () => {
    // ARRANGE — Macie's Security Hub V2 FindingInfoUid is a bare hash, not an ARN
    // ACT
    const result = tryResolveControlId({
      Id: MACIE_BARE_HASH_ID,
      Compliance: { SecurityControlId: 'Macie.SensitiveDataS3Object' },
    });

    // ASSERT — the same value the ARN path would yield for a macie2: ARN. This fallback is
    // deliberately NOT shared with resolveControlId, which refuses to key a row on this field.
    expect(result).toBe('Macie.SensitiveDataS3Object');
  });

  it('returns undefined when neither the ARN nor Compliance resolves', () => {
    // ARRANGE / ACT / ASSERT
    expect(tryResolveControlId({ Id: MACIE_BARE_HASH_ID })).toBeUndefined();
    expect(tryResolveControlId({ Id: MACIE_BARE_HASH_ID, Compliance: {} })).toBeUndefined();
  });

  it('does not round trip a fallback resolution back through getControlIdFromFindingId', () => {
    // ARRANGE — this is the invariant ADR 0010 documents: a fallback-resolved key is not
    // recoverable from the finding id, which is why id-only readers must handle undefined.
    const resolved = tryResolveControlId({
      Id: MACIE_BARE_HASH_ID,
      Compliance: { SecurityControlId: 'Macie.SensitiveDataS3Object' },
    });

    // ACT
    const recovered = getControlIdFromFindingId(MACIE_BARE_HASH_ID);

    // ASSERT
    expect(resolved).toBe('Macie.SensitiveDataS3Object');
    expect(recovered).toBeUndefined();
  });
});

describe('resolveControlId', () => {
  it('returns the control id for a resolvable finding', () => {
    // ARRANGE / ACT
    const result = resolveControlId({
      Id: 'arn:aws:securityhub:us-east-1:123456789012:security-control/EC2.2/finding/abc',
    });

    // ASSERT
    expect(result).toBe('security-control/EC2.2');
  });

  it('ignores Compliance.SecurityControlId rather than keying a row on a bare control id', () => {
    // ARRANGE — the bare `S3.1` is not a partition key; the prefixed form is, and only the ARN
    // carries it. Trusting Compliance here is the hazard ADR 0010 documents.
    const finding = { Id: 'not-an-arn', Compliance: { SecurityControlId: 'S3.1' } };

    // ACT / ASSERT
    expect(() => resolveControlId(finding)).toThrow(UnresolvableControlIdError);
  });

  it('throws UnresolvableControlIdError when the id carries no control id', () => {
    // ARRANGE / ACT / ASSERT — an empty partition key would be rejected by DynamoDB, so this
    // fails fast with the offending finding id instead. A multi-service finding never reaches here;
    // resolveFindingType hands it the mapper's remediation id directly.
    expect(() => resolveControlId({ Id: 'not-an-arn' })).toThrow(UnresolvableControlIdError);
  });
});

describe('tryFindingKeyFromFindingId', () => {
  it('builds a key for a consolidated Security Hub ARN', () => {
    // ARRANGE / ACT
    const key = tryFindingKeyFromFindingId(
      'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc' as FindingId,
    );

    // ASSERT
    expect(key).toEqual({
      findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc',
      findingType: 'security-control/S3.1',
    });
  });

  it('builds a key for a native multi-service ARN', () => {
    // ARRANGE / ACT
    const key = tryFindingKeyFromFindingId(
      'arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def' as FindingId,
    );

    // ASSERT
    expect(key?.findingType).toBe('GuardDuty.IAMUser');
  });

  it('returns undefined for an id that does not encode the partition key', () => {
    // ARRANGE — Macie's Security Hub V2 FindingInfoUid is a bare hash, not an ARN
    // ACT / ASSERT
    expect(tryFindingKeyFromFindingId('9f8e7d6c5b4a392817060f1e2d3c4b5a' as FindingId)).toBeUndefined();
  });
});

describe('partitionFindingIdsByKeyDerivability', () => {
  it('splits derivable ids from non-derivable ids while preserving order', () => {
    // ARRANGE
    const derivable = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc' as FindingId;
    const alsoDerivable = 'arn:aws:macie2:us-east-1:123456789012:finding/xyz' as FindingId;
    const bareHash = '9f8e7d6c5b4a392817060f1e2d3c4b5a' as FindingId;

    // ACT
    const { keys, nonDerivableIds } = partitionFindingIdsByKeyDerivability([derivable, bareHash, alsoDerivable]);

    // ASSERT — callers need the split so they can report the right reason for each id
    expect(keys).toEqual([
      { findingId: derivable, findingType: 'security-control/S3.1' },
      { findingId: alsoDerivable, findingType: 'Macie.SensitiveDataS3Object' },
    ]);
    expect(nonDerivableIds).toEqual([bareHash]);
  });

  it('returns empty collections for empty input', () => {
    // ARRANGE / ACT / ASSERT
    expect(partitionFindingIdsByKeyDerivability([])).toEqual({ keys: [], nonDerivableIds: [] });
  });
});

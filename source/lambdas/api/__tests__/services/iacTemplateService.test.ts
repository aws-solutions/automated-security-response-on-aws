// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { deflate } from 'pako';
import { TemplateResolver } from '../../../common/services/iacGuidanceService';
import { SecurityFindingData } from '../../services/controlPlaceholderMappings';
import { NotFoundError } from '../../../common/utils/httpErrors';
import { IaCTemplateService, getIaCTemplateService } from '../../services/iacTemplateService';
import { buildFindingIdForType, asFindingId } from '../utils';
import type { RemediationHistoryTableItem } from '@asr/data-models';

/** Builds a TemplateResolver stub that always returns the provided content. */
function makeResolver(content: string): TemplateResolver {
  return { resolve: jest.fn().mockResolvedValue(content) };
}

/** Builds a TemplateResolver stub that resolves nothing (template missing). */
function makeEmptyResolver(): TemplateResolver {
  return { resolve: jest.fn().mockResolvedValue(undefined) };
}

/**
 * Builds a fully-typed remediation-history entry for the fetch/render tests.
 * Defaults describe a successful S3.2 remediation; override any field (commonly
 * `findingJSON`) per test. Typed as RemediationHistoryTableItem so tests stay
 * type-safe without casts.
 */
function makeHistoryEntry(overrides: Partial<RemediationHistoryTableItem> = {}): RemediationHistoryTableItem {
  return {
    findingType: 'security-control/S3.2',
    findingId: asFindingId('arn:aws:securityhub:us-east-1:222233334444:security-control/S3.2/finding/abc'),
    accountId: '222233334444',
    resourceId: 'arn:aws:s3:::b',
    resourceType: 'AwsS3Bucket',
    resourceTypeNormalized: 'awss3bucket',
    severity: 'MEDIUM',
    region: 'us-east-1',
    remediationStatus: 'SUCCESS',
    lastUpdatedTime: '2024-01-12T00:00:00Z',
    lastUpdatedBy: 'Automated',
    'findingId#executionId': 'abc#exec-1',
    'lastUpdatedTime#findingId': '2024-01-12T00:00:00Z#abc',
    REMEDIATION_CONSTANT: 'remediation',
    expireAt: 0,
    ...overrides,
  };
}

interface TestAsff extends SecurityFindingData {
  Compliance?: { SecurityControlId?: string; Status?: string };
}

function makeHistoryRepo(asff?: TestAsff) {
  if (!asff) {
    return { findLatestSuccessWithFindingJSON: jest.fn().mockResolvedValue(undefined) };
  }
  return {
    findLatestSuccessWithFindingJSON: jest.fn().mockResolvedValue({
      findingJSON: deflate(JSON.stringify(asff)),
    }),
  };
}

const format = 'cloudformation-yaml';

describe('IaCTemplateService.renderTemplate', () => {
  describe('happy path with valid findingJSON in history', () => {
    it('resolves placeholders from the decompressed ASFF finding', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const service = new IaCTemplateService(
        makeResolver('Bucket: {bucketName}'),
        makeHistoryRepo({
          Compliance: { SecurityControlId: 'S3.2', Status: 'FAILED' },
          Resources: [{ Id: 'arn:aws:s3:::happy-bucket' }],
        }),
      );

      const result = await service.renderTemplate(asFindingId(findingId), format);

      expect(result.content).toBe('Bucket: happy-bucket');
      expect(result.controlId).toBe('S3.2');
      expect(result.filename).toBe('S3.2.yaml.txt');
    });
  });

  describe('no history payload', () => {
    it('returns unavailable note when no remediation history exists', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const service = new IaCTemplateService(makeResolver('Bucket: {bucketName}'), makeHistoryRepo(undefined));

      const result = await service.renderTemplate(asFindingId(findingId), format);

      expect(result.controlId).toBe('S3.2');
      expect(result.filename).toBe('S3.2-iac-unavailable.txt');
      expect(result.content).toContain('cannot be');
      expect(result.content).toContain('populated yet');
    });
  });

  describe('non-ARN findingId', () => {
    it('throws NotFoundError when controlId cannot be extracted', async () => {
      const service = new IaCTemplateService(makeResolver('x'), makeHistoryRepo(undefined));
      await expect(service.renderTemplate(asFindingId('not-an-arn'), format)).rejects.toThrow(NotFoundError);
    });
  });

  describe('control known but no template shipped', () => {
    it('returns the unavailable note keyed on the customer-facing controlId', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const service = new IaCTemplateService(makeEmptyResolver(), makeHistoryRepo(undefined));

      const result = await service.renderTemplate(asFindingId(findingId), format);

      expect(result.controlId).toBe('S3.2');
      expect(result.filename).toBe('S3.2-iac-unavailable.txt');
      expect(result.content).toContain('Infrastructure-as-Code is not available for control S3.2');
    });
  });

  describe('unexpected errors', () => {
    it('propagates errors from the resolver as exceptions', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const resolver = { resolve: jest.fn().mockRejectedValue(new Error('S3 access denied')) } as TemplateResolver;
      const service = new IaCTemplateService(resolver, makeHistoryRepo(undefined));

      await expect(service.renderTemplate(asFindingId(findingId), format)).rejects.toThrow('S3 access denied');
    });
  });

  describe('corrupt findingJSON', () => {
    it('returns no-finding-data note when decompression fails', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const service = new IaCTemplateService(makeResolver('Bucket: {bucketName}'), {
        findLatestSuccessWithFindingJSON: jest.fn().mockResolvedValue({
          findingJSON: new Uint8Array([0, 1, 2, 3]),
        }),
      });

      const result = await service.renderTemplate(asFindingId(findingId), format);
      expect(result.filename).toBe('S3.2-iac-unavailable.txt');
    });

    it('returns no-finding-data note when parsed JSON is not an object', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const service = new IaCTemplateService(makeResolver('x'), {
        findLatestSuccessWithFindingJSON: jest.fn().mockResolvedValue({
          findingJSON: deflate('"just a string"'),
        }),
      });

      const result = await service.renderTemplate(asFindingId(findingId), format);
      expect(result.filename).toBe('S3.2-iac-unavailable.txt');
    });
  });

  describe('no template but history exists', () => {
    it('returns no-template note with correct controlId', async () => {
      const findingId = buildFindingIdForType('security-control/IAM.3');
      const service = new IaCTemplateService(
        makeEmptyResolver(),
        makeHistoryRepo({
          Compliance: { SecurityControlId: 'IAM.3' },
          Resources: [{ Id: 'arn:aws:iam::123456789012:user/test' }],
        }),
      );

      const result = await service.renderTemplate(asFindingId(findingId), format);
      expect(result.controlId).toBe('IAM.3');
      expect(result.content).toContain('does not ship');
    });
  });

  describe('untrusted history controlId sanitization', () => {
    it('sanitizes a control ID resolved from ASFF history before using it as an S3/template key', async () => {
      // A non-ARN findingId forces the controlId to come from the (untrusted)
      // history Compliance.SecurityControlId. Disallowed characters (here a
      // path-traversal attempt) must be stripped before reaching the resolver.
      const resolver = makeEmptyResolver();
      const service = new IaCTemplateService(
        resolver,
        makeHistoryRepo({
          Compliance: { SecurityControlId: '../../etc/passwd\x00' },
          Resources: [{ Id: 'arn:aws:s3:::bucket' }],
        }),
      );

      const result = await service.renderTemplate(asFindingId('not-an-arn'), format);

      // sanitizeControlId keeps [a-zA-Z0-9/.-]; the null byte is dropped.
      expect(result.controlId).toBe('../../etc/passwd');
      expect(result.controlId).not.toContain('\x00');
      expect(resolver.resolve).toHaveBeenCalledWith('../../etc/passwd', 'cloudformation');
    });

    it('leaves a valid control ID unchanged', async () => {
      const findingId = buildFindingIdForType('security-control/S3.2');
      const service = new IaCTemplateService(
        makeResolver('Bucket: {bucketName}'),
        makeHistoryRepo({
          Compliance: { SecurityControlId: 'S3.2', Status: 'FAILED' },
          Resources: [{ Id: 'arn:aws:s3:::valid-bucket' }],
        }),
      );

      const result = await service.renderTemplate(asFindingId(findingId), format);

      expect(result.controlId).toBe('S3.2');
    });
  });
});

describe('IaCTemplateService placeholder replacement', () => {
  it('does not re-substitute a placeholder injected by an earlier replacement value', async () => {
    // S3.2 maps {bucketName} from the bucket name. The bucket name itself
    // contains the literal text "{bucketName}" — a single-pass replacement must
    // leave that injected token untouched rather than substituting it again.
    const findingId = buildFindingIdForType('security-control/S3.2');
    const service = new IaCTemplateService(
      makeResolver('Name: {bucketName}'),
      makeHistoryRepo({
        Compliance: { SecurityControlId: 'S3.2', Status: 'FAILED' },
        Resources: [{ Id: 'arn:aws:s3:::{bucketName}' }],
      }),
    );

    const result = await service.renderTemplate(asFindingId(findingId), format);

    expect(result.content).toBe('Name: {bucketName}');
  });

  it('replaces every occurrence of a token', async () => {
    const findingId = buildFindingIdForType('security-control/S3.2');
    const service = new IaCTemplateService(
      makeResolver('{bucketName}-{bucketName}'),
      makeHistoryRepo({
        Compliance: { SecurityControlId: 'S3.2', Status: 'FAILED' },
        Resources: [{ Id: 'arn:aws:s3:::my-bucket' }],
      }),
    );

    const result = await service.renderTemplate(asFindingId(findingId), format);

    expect(result.content).toBe('my-bucket-my-bucket');
  });

  it('leaves content unchanged when there are no placeholders to apply', async () => {
    // IAM.7 maps a static {accountPasswordPolicy} sentinel; a template without
    // that token round-trips unchanged.
    const findingId = buildFindingIdForType('security-control/IAM.7');
    const service = new IaCTemplateService(
      makeResolver('no tokens here'),
      makeHistoryRepo({
        Compliance: { SecurityControlId: 'IAM.7', Status: 'FAILED' },
        Resources: [{ Id: 'arn:aws:iam::123456789012:account-password-policy' }],
      }),
    );

    const result = await service.renderTemplate(asFindingId(findingId), format);

    expect(result.content).toBe('no tokens here');
  });
});

describe('IaCTemplateService.renderSnippet', () => {
  it('renders a snippet from a supplied placeholder map', async () => {
    const service = new IaCTemplateService(makeResolver('Bucket: {bucketName}'), makeHistoryRepo(undefined));

    const result = await service.renderSnippet('S3.2', format, { bucketName: 'snippet-bucket' });

    expect(result).toBe('Bucket: snippet-bucket');
  });

  it('returns undefined when no template is shipped for the control', async () => {
    const service = new IaCTemplateService(makeEmptyResolver(), makeHistoryRepo(undefined));

    const result = await service.renderSnippet('S3.2', format, { bucketName: 'snippet-bucket' });

    expect(result).toBeUndefined();
  });
});

describe('IaCTemplateService.fetchFindingForDownload and renderTemplateForFinding', () => {
  it('fetchFindingForDownload returns the latest successful history entry', async () => {
    // ARRANGE
    const entry = makeHistoryEntry({ findingJSON: deflate('{}') });
    const historyRepo = { findLatestSuccessWithFindingJSON: jest.fn().mockResolvedValue(entry) };
    const service = new IaCTemplateService(makeResolver('x'), historyRepo);
    const findingId = asFindingId(buildFindingIdForType('security-control/S3.2'));

    // ACT
    const result = await service.fetchFindingForDownload(findingId);

    // ASSERT
    expect(result).toBe(entry);
    expect(historyRepo.findLatestSuccessWithFindingJSON).toHaveBeenCalledWith(findingId);
  });

  it('renderTemplateForFinding renders from a pre-fetched entry without re-reading DynamoDB', async () => {
    // ARRANGE: an entry carrying the compressed ASFF; the repo must NOT be queried again
    const asff = { Compliance: { SecurityControlId: 'S3.2', Status: 'FAILED' }, Resources: [{ Id: 'arn:aws:s3:::b' }] };
    const historyRepo = makeHistoryRepo(undefined) as { findLatestSuccessWithFindingJSON: jest.Mock };
    const service = new IaCTemplateService(makeResolver('Bucket: {bucketName}'), historyRepo);
    const findingId = asFindingId(buildFindingIdForType('security-control/S3.2'));

    // ACT
    const result = await service.renderTemplateForFinding(
      makeHistoryEntry({ findingJSON: deflate(JSON.stringify(asff)) }),
      findingId,
      format,
    );

    // ASSERT
    expect(result.content).toBe('Bucket: b');
    expect(historyRepo.findLatestSuccessWithFindingJSON).not.toHaveBeenCalled();
  });

  it('renderTemplateForFinding returns the no-finding-data note when the entry is null', async () => {
    // ARRANGE
    const service = new IaCTemplateService(makeResolver('Bucket: {bucketName}'), makeHistoryRepo(undefined));
    const findingId = asFindingId(buildFindingIdForType('security-control/S3.2'));

    // ACT
    const result = await service.renderTemplateForFinding(null, findingId, format);

    // ASSERT
    expect(result.filename).toBe('S3.2-iac-unavailable.txt');
    expect(result.content).toContain('populated yet');
  });
});

describe('getIaCTemplateService factory', () => {
  it('builds an IaCTemplateService from the validated environment', () => {
    // envSetup.ts populates IAC_TEMPLATES_BUCKET, REMEDIATION_HISTORY_TABLE_NAME,
    // and FINDINGS_TABLE_NAME, so the factory wires repos/resolver without errors.
    const service = getIaCTemplateService();

    expect(service).toBeInstanceOf(IaCTemplateService);
  });

  it('memoizes the instance across calls (one per Lambda container)', () => {
    expect(getIaCTemplateService()).toBe(getIaCTemplateService());
  });
});

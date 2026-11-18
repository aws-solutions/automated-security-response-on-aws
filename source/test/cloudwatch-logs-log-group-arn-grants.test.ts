// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  actionsOf,
  administratorPolicyDocuments,
  auxiliaryStackPolicyDocuments,
  memberPolicyDocuments,
  memberRolesPolicyDocuments,
  NamedPolicyDocument,
  PolicyStatementJson,
} from './iam-policy-documents';

// CloudWatch Logs authorizes only these actions against a log stream ARN; every other action needs a log group ARN.
const LOG_STREAM_ACTIONS = new Set([
  'logs:PutLogEvents',
  'logs:GetLogEvents',
  'logs:CreateLogStream',
  'logs:DeleteLogStream',
]);

const PSEUDO_PARAMETER_VALUES: Record<string, string> = {
  'AWS::Partition': 'aws',
  'AWS::Region': 'us-east-1',
  'AWS::AccountId': '111111111111',
};

/** Marks a token that cannot be resolved locally, such as `Fn::GetAtt`, so its statement fails closed. */
const UNRESOLVED_TOKEN = '<unresolved>';

interface UncoveredLogGroupGrant {
  readonly policyName: string;
  readonly action: string;
  readonly resource: string;
}

function renderResource(resource: unknown): string {
  if (typeof resource === 'string') return resource;
  if (resource !== null && typeof resource === 'object') {
    if ('Fn::Join' in resource && Array.isArray(resource['Fn::Join'])) {
      const [delimiter, parts] = resource['Fn::Join'];
      if (typeof delimiter === 'string' && Array.isArray(parts)) return parts.map(renderResource).join(delimiter);
    }
    if ('Ref' in resource && typeof resource.Ref === 'string' && resource.Ref in PSEUDO_PARAMETER_VALUES) {
      return PSEUDO_PARAMETER_VALUES[resource.Ref];
    }
  }
  return UNRESOLVED_TOKEN;
}

function resourcesOf(statement: PolicyStatementJson): string[] {
  const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
  return resources.map(renderResource);
}

/** The log group pattern a resource must also be granted on: the resource itself, minus any log stream suffix. */
function logGroupPatternOf(resource: string): string {
  const logGroupMarker = ':log-group:';
  const markerIndex = resource.indexOf(logGroupMarker);
  if (markerIndex === -1) return resource;
  const nameStart = markerIndex + logGroupMarker.length;
  const streamSuffixIndex = resource.indexOf(':', nameStart);
  return streamSuffixIndex === -1 ? resource : resource.slice(0, streamSuffixIndex);
}

function iamPatternToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`);
}

/** Whether a granted resource pattern covers every ARN the required log group pattern can match. */
function coversLogGroupPattern(grantedResource: string, requiredPattern: string): boolean {
  if (grantedResource.includes(UNRESOLVED_TOKEN) || logGroupPatternOf(grantedResource) !== grantedResource) {
    return false;
  }
  return iamPatternToRegex(grantedResource).test(requiredPattern);
}

function uncoveredLogGroupGrantsOf(document: NamedPolicyDocument): UncoveredLogGroupGrant[] {
  const allowStatements = document.statements.filter((statement) => statement.Effect === 'Allow');
  const isGrantedOn = (action: string, requiredPattern: string): boolean =>
    allowStatements.some(
      (statement) =>
        actionsOf(statement).includes(action) &&
        resourcesOf(statement).some((grantedResource) => coversLogGroupPattern(grantedResource, requiredPattern)),
    );

  return allowStatements.flatMap((statement) =>
    actionsOf(statement)
      .filter((action) => action.startsWith('logs:') && !LOG_STREAM_ACTIONS.has(action))
      .flatMap((action) =>
        resourcesOf(statement)
          .filter(
            (resource) => resource.includes(UNRESOLVED_TOKEN) || !isGrantedOn(action, logGroupPatternOf(resource)),
          )
          .map((resource) => ({ policyName: document.policyName, action, resource })),
      ),
  );
}

describe('CloudWatch Logs grants', () => {
  test('every log group action granted on a log stream ARN is also granted on its log group ARN', () => {
    // ARRANGE
    const policyDocuments = [
      ...memberRolesPolicyDocuments(),
      ...memberPolicyDocuments(),
      ...administratorPolicyDocuments(),
      ...auxiliaryStackPolicyDocuments(),
    ];

    // ACT
    const uncoveredGrants = policyDocuments.flatMap(uncoveredLogGroupGrantsOf);

    // ASSERT
    expect(uncoveredGrants).toEqual([]);
  });
});

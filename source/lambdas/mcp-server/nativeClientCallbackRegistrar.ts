// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Deployment-time custom resource that adds Codex's exact OAuth callback URL to the
 * Cognito app client after the AgentCore gateway URL exists.
 *
 * Codex derives a stable callback identifier from the full MCP server URL. The gateway
 * identifier is assigned by AgentCore during deployment, so CDK cannot calculate the final
 * callback during synthesis without creating a dependency cycle between the Cognito client
 * and the gateway authorizer. This resource resolves that after the gateway URL is known.
 */

import { createHash } from 'node:crypto';
import {
  CognitoIdentityProviderClient,
  DescribeUserPoolClientCommand,
  UpdateUserPoolClientCommand,
  type UpdateUserPoolClientCommandInput,
  type UserPoolClientType,
} from '@aws-sdk/client-cognito-identity-provider';

const cognito = new CognitoIdentityProviderClient({});

// Properties that DescribeUserPoolClient returns and UpdateUserPoolClient accepts. We read
// the current client and echo these back so updating CallbackURLs never drops an existing
// setting (UpdateUserPoolClient replaces the whole client, it does not patch).
const UPDATEABLE_CLIENT_PROPERTIES = [
  'ClientName',
  'RefreshTokenValidity',
  'AccessTokenValidity',
  'IdTokenValidity',
  'TokenValidityUnits',
  'ReadAttributes',
  'WriteAttributes',
  'ExplicitAuthFlows',
  'SupportedIdentityProviders',
  'LogoutURLs',
  'DefaultRedirectURI',
  'AllowedOAuthFlows',
  'AllowedOAuthScopes',
  'AllowedOAuthFlowsUserPoolClient',
  'AnalyticsConfiguration',
  'PreventUserExistenceErrors',
  'EnableTokenRevocation',
  'EnablePropagateAdditionalUserContextData',
  'AuthSessionValidity',
  'RefreshTokenRotation',
] as const satisfies readonly (keyof UserPoolClientType)[];

interface CustomResourceEvent {
  readonly RequestType: 'Create' | 'Update' | 'Delete' | string;
  readonly PhysicalResourceId?: string;
  readonly ResponseURL?: string;
  readonly StackId?: string;
  readonly RequestId?: string;
  readonly LogicalResourceId?: string;
  readonly ResourceProperties?: Record<string, unknown>;
}

interface CustomResourceContext {
  readonly logStreamName: string;
}

interface RegistrarResult {
  readonly PhysicalResourceId: string;
  readonly Data: { readonly CodexCallbackUrl: string };
}

function requireString(properties: Record<string, unknown>, name: string): string {
  const value = properties[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

function requireStringArray(properties: Record<string, unknown>, name: string): string[] {
  const value = properties[name];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new Error(`${name} must be an array of non-empty strings`);
  }
  return value as string[];
}

function optionalCallbackUrls(properties: Record<string, unknown>, name: string): string[] {
  const value = properties[name];
  if (value === undefined || value === null) {
    return [];
  }
  if (typeof value === 'string') {
    return value.split(/\r?\n/);
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`${name} must be an array of strings`);
  }
  return value as string[];
}

// Cognito compares redirect URIs character for character. Whitespace around a template
// parameter is accidental, but the trailing slash is part of the path and must be preserved
// because native clients may send either `/callback` or `/callback/`.
function trimCallbackUrl(value: string): string {
  return value.trim();
}

const LOOPBACK_HOSTNAMES = ['localhost', '127.0.0.1', '[::1]', '::1'];

/**
 * Gate on operator-supplied redirect URIs.
 *
 * The gateway app client is a PUBLIC PKCE client, so anything in its callback list is a
 * place Cognito will hand an authorization code to. PKCE stops a stolen code from being
 * redeemed without the verifier, but an attacker-controlled URI in the list is still an
 * interception surface — so this fails the deployment closed rather than registering a URI
 * it cannot vouch for.
 *
 * Accepts exactly what an MCP client can legitimately use: HTTPS anywhere, or plain HTTP
 * restricted to loopback (the only case Cognito itself permits over HTTP, and what native
 * CLI clients bind). Everything else is refused, which rejects the schemes that turn a
 * redirect into code execution or exfiltration — javascript:, data:, file:, ftp:.
 */
function assertRegistrableCallbackUrl(value: string, source = 'AdditionalCallbackUrls'): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${source} contains a value that is not a valid absolute URL: ${value}`);
  }
  // Cognito rejects redirect URIs carrying a fragment; catch it here so the failure names
  // the offending URL instead of surfacing as an opaque Cognito error.
  if (parsed.hash) {
    throw new Error(`${source} entries must not include a fragment: ${value}`);
  }
  if (parsed.protocol === 'https:') {
    return value;
  }
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTNAMES.includes(parsed.hostname)) {
    return value;
  }
  throw new Error(`${source} entries must use https, or http on a loopback host, but got: ${value}`);
}

function codexCallbackUrl(gatewayUrl: string, callbackBaseUrl: string): string {
  const callbackId = createHash('sha256').update(gatewayUrl).digest('base64url').slice(0, 12);
  return `${callbackBaseUrl.replace(/\/$/, '')}/${callbackId}`;
}

export async function handleRequest(event: CustomResourceEvent): Promise<RegistrarResult> {
  const properties = event.ResourceProperties ?? {};
  const userPoolId = requireString(properties, 'UserPoolId');
  const clientId = requireString(properties, 'ClientId');
  const gatewayUrl = requireString(properties, 'GatewayUrl');
  const callbackBaseUrl = requireString(properties, 'CodexCallbackBaseUrl');
  const fixedCallbackUrls = requireStringArray(properties, 'FixedCallbackUrls');
  const physicalResourceId = event.PhysicalResourceId ?? `${userPoolId}/${clientId}/native-client-callbacks`;
  const generatedCodexCallbackUrl = codexCallbackUrl(gatewayUrl, callbackBaseUrl);

  if (event.RequestType === 'Delete') {
    return {
      PhysicalResourceId: physicalResourceId,
      Data: { CodexCallbackUrl: generatedCodexCallbackUrl },
    };
  }

  if (event.RequestType !== 'Create' && event.RequestType !== 'Update') {
    throw new Error(`Unsupported request type: ${event.RequestType}`);
  }

  // Validate ResponseURL before any Cognito write. sendCloudFormationResponse also
  // checks it, but that runs AFTER the client update — so a malformed event would
  // leave the app client changed with no way to report success to CloudFormation,
  // stranding the stack. Rejecting it here keeps the side effect and the ability to
  // report its outcome together. (Delete returns above without side effects, so it
  // is intentionally not gated here — a bad URL must not wedge a rollback.)
  if (!event.ResponseURL) {
    throw new Error('Custom resource event has no ResponseURL; refusing to update the app client.');
  }

  // Validated only on Create/Update, never on Delete: a rejected URL puts the resource in
  // CREATE_FAILED, and CloudFormation rolls that back with a Delete carrying the same bad
  // property. Validating there too would throw during the rollback and leave the stack
  // undeletable.
  //
  // The top-level CommaDelimitedList is transported across the nested-stack boundary as a
  // newline-delimited string. Empty entries are dropped before validation so the default
  // (no extra URLs) does not fail deployment. Arrays remain accepted for safe updates from
  // templates deployed before the string transport was introduced.
  const additionalCallbackUrls = optionalCallbackUrls(properties, 'AdditionalCallbackUrls')
    .map(trimCallbackUrl)
    .filter((url) => url.length > 0)
    .map((url) => assertRegistrableCallbackUrl(url));

  const response = await cognito.send(
    new DescribeUserPoolClientCommand({ UserPoolId: userPoolId, ClientId: clientId }),
  );
  if (!response.UserPoolClient) {
    throw new Error(`Cognito app client ${clientId} was not found in user pool ${userPoolId}`);
  }

  const existingClient = response.UserPoolClient;
  // Echo back the client's existing settings so replacing CallbackURLs never drops one.
  // Every name in UPDATEABLE_CLIENT_PROPERTIES is a key shared by the describe output and
  // the update input, so copying the value across preserves its type.
  const preservedSettings: Partial<UpdateUserPoolClientCommandInput> = {};
  for (const propertyName of UPDATEABLE_CLIENT_PROPERTIES) {
    const value = existingClient[propertyName];
    if (value !== undefined) {
      Object.assign(preservedSettings, { [propertyName]: value });
    }
  }
  const updateRequest: UpdateUserPoolClientCommandInput = {
    ...preservedSettings,
    UserPoolId: userPoolId,
    ClientId: clientId,
    // Validate every source that lands in CallbackURLs, not just the operator-supplied
    // AdditionalCallbackUrls. UpdateUserPoolClient replaces the whole list on this public
    // PKCE client, so the fixed callbacks and the generated Codex URL are equally part of the
    // set a redirect would be honored against; checking only one source leaves the others as
    // an unvalidated interception surface. These two are solution-controlled so a rejection
    // here means a build/synthesis defect rather than bad operator input, but the check is
    // cheap and keeps the whole list held to one rule.
    CallbackURLs: [
      ...new Set([
        ...fixedCallbackUrls.map((url) => assertRegistrableCallbackUrl(url, 'FixedCallbackUrls')),
        ...additionalCallbackUrls,
        assertRegistrableCallbackUrl(generatedCodexCallbackUrl, 'CodexCallbackUrl'),
      ]),
    ],
  };

  await cognito.send(new UpdateUserPoolClientCommand(updateRequest));

  return {
    PhysicalResourceId: physicalResourceId,
    Data: { CodexCallbackUrl: generatedCodexCallbackUrl },
  };
}

async function sendCloudFormationResponse(
  event: CustomResourceEvent,
  context: CustomResourceContext,
  status: 'SUCCESS' | 'FAILED',
  result?: RegistrarResult,
  reason?: string,
): Promise<void> {
  // ResponseURL is the pre-signed S3 URL CloudFormation provides for the custom
  // resource callback. It is typed optional because the interface models every
  // field CloudFormation may send, but a real Create/Update/Delete invocation
  // always carries it. Validate rather than cast (ADR 0001): with no URL there is
  // nowhere to report the result, so surface that as an explicit error instead of
  // a non-null assertion that would fail opaquely inside fetch.
  const responseUrl = event.ResponseURL;
  if (!responseUrl) {
    throw new Error('Custom resource event has no ResponseURL; cannot send the CloudFormation response.');
  }
  const responseBody = JSON.stringify({
    Status: status,
    Reason: reason ?? `See CloudWatch Logs: ${context.logStreamName}`,
    PhysicalResourceId: result?.PhysicalResourceId ?? event.PhysicalResourceId ?? context.logStreamName,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
    NoEcho: false,
    Data: result?.Data ?? {},
  });
  const response = await fetch(responseUrl, {
    method: 'PUT',
    headers: {
      'content-type': '',
      'content-length': Buffer.byteLength(responseBody).toString(),
    },
    body: responseBody,
  });
  if (!response.ok) {
    throw new Error(`CloudFormation response failed with HTTP ${response.status}`);
  }
}

export const handler = async (event: CustomResourceEvent, context: CustomResourceContext): Promise<RegistrarResult> => {
  try {
    const result = await handleRequest(event);
    await sendCloudFormationResponse(event, context, 'SUCCESS', result);
    return result;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    // Best-effort failure callback. sendCloudFormationResponse itself throws when the
    // event has no ResponseURL (and fetch can fail), and letting that throw escape here
    // would replace the ORIGINAL error with a generic "no ResponseURL" one — masking the
    // real cause and still failing the handler. Swallow the reporting failure, log it, and
    // always rethrow the original error so the true reason surfaces.
    try {
      await sendCloudFormationResponse(event, context, 'FAILED', undefined, reason);
    } catch (reportError) {
      console.error('Failed to send the FAILED CloudFormation response; rethrowing the original error', {
        originalError: reason,
        reportError: reportError instanceof Error ? reportError.message : String(reportError),
      });
    }
    throw error;
  }
};

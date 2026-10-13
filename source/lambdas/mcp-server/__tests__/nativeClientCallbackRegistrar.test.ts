// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { mockClient } from 'aws-sdk-client-mock';
import {
  CognitoIdentityProviderClient,
  DescribeUserPoolClientCommand,
  UpdateUserPoolClientCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { handleRequest, handler } from '../nativeClientCallbackRegistrar';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

// The fixed native-client callbacks and Codex base URL are supplied to the handler via
// custom-resource properties (the construct owns them). Mirror the construct's values here.
const KIRO_CLI_OAUTH_CALLBACK_URL = 'http://localhost:8770';
const KIRO_IDE_OAUTH_CALLBACK_URL = 'http://localhost:8770/oauth/callback';
const CLAUDE_CODE_OAUTH_CALLBACK_URL = 'http://localhost:8772/callback';
const CODEX_OAUTH_CALLBACK_BASE_URL = 'http://127.0.0.1:8780/callback';

const GATEWAY_URL = 'https://so0111-mcp-gateway-e36ufscuhp.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp';
const CODEX_CALLBACK_URL = 'http://127.0.0.1:8780/callback/SJCzLil9u_7J';

type RegistrarEvent = Parameters<typeof handleRequest>[0];

function event(requestType: RegistrarEvent['RequestType']): RegistrarEvent {
  return {
    RequestType: requestType,
    ResponseURL: 'https://cloudformation-custom-resource-response.example.com/abc',
    ResourceProperties: {
      UserPoolId: 'us-east-1_pool',
      ClientId: 'client-id',
      GatewayUrl: GATEWAY_URL,
      CodexCallbackBaseUrl: CODEX_OAUTH_CALLBACK_BASE_URL,
      FixedCallbackUrls: [KIRO_CLI_OAUTH_CALLBACK_URL, KIRO_IDE_OAUTH_CALLBACK_URL, CLAUDE_CODE_OAUTH_CALLBACK_URL],
    },
  };
}

function eventWithAdditional(additionalCallbackUrls: unknown): RegistrarEvent {
  const base = event('Create');
  return {
    ...base,
    ResourceProperties: { ...base.ResourceProperties, AdditionalCallbackUrls: additionalCallbackUrls },
  };
}

function callbackUrlsOf(): unknown {
  const update = cognitoMock.commandCalls(UpdateUserPoolClientCommand)[0];
  return update.args[0].input.CallbackURLs;
}

beforeEach(() => {
  cognitoMock.reset();
  cognitoMock.on(DescribeUserPoolClientCommand).resolves({
    UserPoolClient: { ClientName: 'SO0111-ASR-MCP-Gateway-Client' },
  });
  cognitoMock.on(UpdateUserPoolClientCommand).resolves({});
});

describe('MCP native-client callback registrar', () => {
  it('derives Codex callback ID from the deployed gateway URL and preserves client settings', async () => {
    cognitoMock.on(DescribeUserPoolClientCommand).resolves({
      UserPoolClient: {
        ClientName: 'SO0111-ASR-MCP-Gateway-Client',
        AllowedOAuthFlows: ['code'],
        AllowedOAuthScopes: ['openid', 'email', 'profile'],
        AllowedOAuthFlowsUserPoolClient: true,
        EnableTokenRevocation: true,
      },
    });

    const result = await handleRequest(event('Create'));

    expect(result.Data.CodexCallbackUrl).toBe(CODEX_CALLBACK_URL);

    const describeCall = cognitoMock.commandCalls(DescribeUserPoolClientCommand)[0];
    expect(describeCall.args[0].input).toEqual({ UserPoolId: 'us-east-1_pool', ClientId: 'client-id' });

    const updateCall = cognitoMock.commandCalls(UpdateUserPoolClientCommand)[0];
    expect(updateCall.args[0].input).toMatchObject({
      UserPoolId: 'us-east-1_pool',
      ClientId: 'client-id',
      ClientName: 'SO0111-ASR-MCP-Gateway-Client',
      AllowedOAuthFlows: ['code'],
      AllowedOAuthScopes: ['openid', 'email', 'profile'],
      AllowedOAuthFlowsUserPoolClient: true,
      EnableTokenRevocation: true,
      CallbackURLs: [
        KIRO_CLI_OAUTH_CALLBACK_URL,
        KIRO_IDE_OAUTH_CALLBACK_URL,
        CLAUDE_CODE_OAUTH_CALLBACK_URL,
        CODEX_CALLBACK_URL,
      ],
    });
  });

  it('does not call Cognito while CloudFormation deletes the registrar', async () => {
    const result = await handleRequest({ ...event('Delete'), PhysicalResourceId: 'existing-physical-id' });

    expect(cognitoMock.calls()).toHaveLength(0);
    expect(result.PhysicalResourceId).toBe('existing-physical-id');
  });

  describe('operator-supplied additional callback URLs', () => {
    it('registers an https callback alongside the built-in client callbacks', async () => {
      await handleRequest(eventWithAdditional('https://ide.example.com/oauth/callback'));

      expect(callbackUrlsOf()).toEqual([
        KIRO_CLI_OAUTH_CALLBACK_URL,
        KIRO_IDE_OAUTH_CALLBACK_URL,
        CLAUDE_CODE_OAUTH_CALLBACK_URL,
        'https://ide.example.com/oauth/callback',
        CODEX_CALLBACK_URL,
      ]);
    });

    it('allows plain http only on a loopback host, which is what native CLI clients bind', async () => {
      await handleRequest(eventWithAdditional('http://localhost:9999/cb\nhttp://127.0.0.1:9998/cb'));

      expect(callbackUrlsOf()).toEqual(
        expect.arrayContaining(['http://localhost:9999/cb', 'http://127.0.0.1:9998/cb']),
      );
    });

    it('preserves a trailing slash because it is part of the exact client redirect URI', async () => {
      await handleRequest(eventWithAdditional(['  https://ide.example.com/callback/  ']));

      expect(callbackUrlsOf()).toEqual(expect.arrayContaining(['https://ide.example.com/callback/']));
    });

    it('treats an empty CommaDelimitedList parameter as no extra URLs rather than failing', async () => {
      await handleRequest(eventWithAdditional(''));

      expect(callbackUrlsOf()).toEqual([
        KIRO_CLI_OAUTH_CALLBACK_URL,
        KIRO_IDE_OAUTH_CALLBACK_URL,
        CLAUDE_CODE_OAUTH_CALLBACK_URL,
        CODEX_CALLBACK_URL,
      ]);
    });

    it('accepts the previous array property shape during stack updates', async () => {
      await handleRequest(eventWithAdditional(['https://legacy.example.com/oauth/callback']));

      expect(callbackUrlsOf()).toEqual(expect.arrayContaining(['https://legacy.example.com/oauth/callback']));
    });

    it('registers only the built-in callbacks when the property is absent', async () => {
      await handleRequest(event('Create'));

      expect(callbackUrlsOf()).toEqual([
        KIRO_CLI_OAUTH_CALLBACK_URL,
        KIRO_IDE_OAUTH_CALLBACK_URL,
        CLAUDE_CODE_OAUTH_CALLBACK_URL,
        CODEX_CALLBACK_URL,
      ]);
    });

    // Each of these would turn an allowlisted redirect into code execution, local file
    // access, or plaintext exfiltration of an authorization code.
    it.each([
      ['javascript://ide.example.com/callback'],
      ['Javascript://ide.example.com/callback'],
      ['data:text/html,<script>fetch(location)</script>'],
      ['file:///tmp/callback'],
      ['ftp://ide.example.com/callback'],
    ])('refuses the deployment for scheme in %s', async (url) => {
      await expect(handleRequest(eventWithAdditional([url]))).rejects.toThrow(
        /must use https, or http on a loopback host/,
      );
    });

    it('refuses plain http on a non-loopback host, which would send codes in cleartext', async () => {
      await expect(handleRequest(eventWithAdditional(['http://ide.example.com/callback']))).rejects.toThrow(
        /must use https, or http on a loopback host/,
      );
    });

    it('refuses a fragment, which Cognito rejects for redirect URIs', async () => {
      await expect(handleRequest(eventWithAdditional(['https://ide.example.com/callback#/code']))).rejects.toThrow(
        /must not include a fragment/,
      );
    });

    it('refuses a value that is not an absolute URL', async () => {
      await expect(handleRequest(eventWithAdditional(['/oauth/callback']))).rejects.toThrow(/not a valid absolute URL/);
    });

    it('does not validate on Delete, so a bad URL cannot wedge the rollback', async () => {
      const base = eventWithAdditional(['javascript://evil.example.com']);

      const result = await handleRequest({ ...base, RequestType: 'Delete' });

      expect(cognitoMock.calls()).toHaveLength(0);
      expect(result.Data.CodexCallbackUrl).toBe(CODEX_CALLBACK_URL);
    });

    it('rejects a non-string entry before calling Cognito', async () => {
      await expect(handleRequest(eventWithAdditional([42]))).rejects.toThrow(
        'AdditionalCallbackUrls must be an array of strings',
      );
      expect(cognitoMock.calls()).toHaveLength(0);
    });
  });

  describe('validation covers every source that lands in CallbackURLs', () => {
    // UpdateUserPoolClient replaces the whole list on this public PKCE client, so the fixed
    // callbacks and the generated Codex URL are as much a redirect surface as the operator's
    // AdditionalCallbackUrls. The registrar used to validate only the latter.
    it('refuses a FixedCallbackUrls entry with an unsupported scheme', async () => {
      const base = event('Create');
      const badFixed = {
        ...base,
        ResourceProperties: {
          ...base.ResourceProperties,
          FixedCallbackUrls: [KIRO_CLI_OAUTH_CALLBACK_URL, 'javascript://evil.example.com/callback'],
        },
      };

      await expect(handleRequest(badFixed)).rejects.toThrow(
        /FixedCallbackUrls entries must use https, or http on a loopback host/,
      );
      expect(cognitoMock.commandCalls(UpdateUserPoolClientCommand)).toHaveLength(0);
    });

    it('refuses a Codex callback base URL that resolves to an unsupported scheme', async () => {
      const base = event('Create');
      const badCodex = {
        ...base,
        ResourceProperties: { ...base.ResourceProperties, CodexCallbackBaseUrl: 'ftp://exfil.example.com/callback' },
      };

      await expect(handleRequest(badCodex)).rejects.toThrow(
        /CodexCallbackUrl entries must use https, or http on a loopback host/,
      );
      expect(cognitoMock.commandCalls(UpdateUserPoolClientCommand)).toHaveLength(0);
    });
  });

  it('rejects malformed custom-resource properties before calling Cognito', async () => {
    await expect(
      handleRequest({
        ...event('Create'),
        ResourceProperties: { ...event('Create').ResourceProperties, GatewayUrl: '' },
      }),
    ).rejects.toThrow('GatewayUrl must be a non-empty string');
    expect(cognitoMock.calls()).toHaveLength(0);
  });

  it('refuses to update the app client when the event has no ResponseURL', async () => {
    // Without a ResponseURL there is nowhere to report the outcome, so the update
    // must be rejected before it happens rather than after — otherwise the client
    // is changed with no way to signal CloudFormation.
    const { ResponseURL: _omit, ...noResponseUrl } = event('Create');

    await expect(handleRequest(noResponseUrl)).rejects.toThrow(/no ResponseURL/);
    expect(cognitoMock.calls()).toHaveLength(0);
  });
});

// The exported handler wraps handleRequest with the CloudFormation response callback.
// Nothing covered it, which left the branch that matters least often and costs most when
// wrong: what the stack sees when the registrar fails.
describe('MCP native-client callback registrar — CloudFormation response', () => {
  const RESPONSE_URL = 'https://cloudformation-custom-resource-response.example.com/abc';

  function cloudFormationEvent(requestType: RegistrarEvent['RequestType'] = 'Create'): RegistrarEvent {
    return {
      ...event(requestType),
      StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/ASR-Admin/abc',
      RequestId: 'request-1',
      LogicalResourceId: 'McpNativeClientCallbackRegistration',
    } as RegistrarEvent;
  }

  const lambdaContext = { logStreamName: 'log-stream-1' };
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  /** The single response body PUT to the pre-signed URL. */
  function sentResponse(): Record<string, unknown> {
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(RESPONSE_URL);
    expect(init.method).toBe('PUT');
    return JSON.parse(init.body as string);
  }

  it('reports SUCCESS with the stack identifiers CloudFormation matches the response on', async () => {
    // CloudFormation correlates the callback by StackId + RequestId + LogicalResourceId. Get
    // one wrong and the stack waits out its timeout even though the work succeeded.
    await handler(cloudFormationEvent(), lambdaContext);

    expect(sentResponse()).toMatchObject({
      Status: 'SUCCESS',
      StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/ASR-Admin/abc',
      RequestId: 'request-1',
      LogicalResourceId: 'McpNativeClientCallbackRegistration',
    });
  });

  it('reports FAILED with the real reason and rethrows the original error', async () => {
    cognitoMock.on(DescribeUserPoolClientCommand).rejects(new Error('user pool client not found'));

    await expect(handler(cloudFormationEvent(), lambdaContext)).rejects.toThrow(/user pool client not found/);

    expect(sentResponse()).toMatchObject({ Status: 'FAILED', Reason: 'user pool client not found' });
  });

  it('rethrows the original error even when the failure callback itself cannot be sent', async () => {
    // The masking bug this guards: if reporting the failure throws, that error must not
    // replace the real cause — an operator would otherwise debug the callback instead of
    // the actual problem.
    cognitoMock.on(DescribeUserPoolClientCommand).rejects(new Error('user pool client not found'));
    fetchMock.mockRejectedValue(new Error('pre-signed URL expired'));

    await expect(handler(cloudFormationEvent(), lambdaContext)).rejects.toThrow(/user pool client not found/);
  });

  it('fails when CloudFormation rejects the response, rather than reporting success', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 403 });

    await expect(handler(cloudFormationEvent(), lambdaContext)).rejects.toThrow(/HTTP 403/);
  });
});

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnDocument } from 'aws-cdk-lib/aws-ssm';
import { Aspects, Stack } from 'aws-cdk-lib';
import SsmDocRateLimit from './ssm-doc-rate-limit';
import { WaitProvider } from './wait-provider';
import { Template } from 'aws-cdk-lib/assertions';

describe('SSM doc rate limit aspect', function () {
  it('configures dependencies for single document', function () {
    const stack = new Stack();
    const serviceToken = 'my-token';
    const waitProvider = WaitProvider.fromServiceToken(stack, 'WaitProvider', serviceToken);
    Aspects.of(stack).add(new SsmDocRateLimit(waitProvider));
    const content = {};
    new CfnDocument(stack, 'Document', { content });
    const template = Template.fromStack(stack);

    const documents = template.findResources('AWS::SSM::Document', { Properties: { Content: content } });
    const documentLogicalIds = Object.getOwnPropertyNames(documents);
    expect(documentLogicalIds).toHaveLength(1);
    const documentLogicalId = documentLogicalIds[0];
    const document = documents[documentLogicalId];

    const createWaits = template.findResources('Custom::Wait', {
      Properties: {
        CreateIntervalSeconds: 1,
        UpdateIntervalSeconds: 1,
        DeleteIntervalSeconds: 0,
        ServiceToken: serviceToken,
      },
    });
    const createWaitLogicalIds = Object.getOwnPropertyNames(createWaits);
    expect(createWaitLogicalIds).toHaveLength(1);
    const createWaitLogicalId = createWaitLogicalIds[0];
    expect(document.DependsOn).toEqual(expect.arrayContaining([createWaitLogicalId]));

    const deleteWaits = template.findResources('Custom::Wait', {
      Properties: {
        CreateIntervalSeconds: 0,
        UpdateIntervalSeconds: 0,
        DeleteIntervalSeconds: 0.5,
        ServiceToken: serviceToken,
      },
    });
    const deleteWaitLogicalIds = Object.getOwnPropertyNames(deleteWaits);
    expect(deleteWaitLogicalIds).toHaveLength(1);
    const deleteWait = deleteWaits[deleteWaitLogicalIds[0]];
    expect(deleteWait.DependsOn).toEqual(expect.arrayContaining([documentLogicalId]));
  });

  it('configures dependencies for many documents', function () {
    const stack = new Stack();
    const serviceToken = 'my-token';
    const waitProvider = WaitProvider.fromServiceToken(stack, 'WaitProvider', serviceToken);
    Aspects.of(stack).add(new SsmDocRateLimit(waitProvider));
    const content = {};
    const numDocuments = 12;
    for (let i = 0; i < numDocuments; ++i) {
      new CfnDocument(stack, `Document${i}`, { content });
    }
    const template = Template.fromStack(stack);
    expect(template).toMatchSnapshot();

    const documents = template.findResources('AWS::SSM::Document', { Properties: { Content: content } });
    const documentLogicalIds = Object.getOwnPropertyNames(documents);
    expect(documentLogicalIds).toHaveLength(numDocuments);

    const expectedBatchSize = 5;

    const createWaits = template.findResources('Custom::Wait', {
      Properties: {
        CreateIntervalSeconds: 1,
        UpdateIntervalSeconds: 1,
        DeleteIntervalSeconds: 0,
        ServiceToken: serviceToken,
      },
    });
    const createWaitLogicalIds = Object.getOwnPropertyNames(createWaits);
    expect(createWaitLogicalIds).toHaveLength(Math.ceil(numDocuments / expectedBatchSize));

    const deleteWaits = template.findResources('Custom::Wait', {
      Properties: {
        CreateIntervalSeconds: 0,
        UpdateIntervalSeconds: 0,
        DeleteIntervalSeconds: 0.5,
        ServiceToken: serviceToken,
      },
    });
    const deleteWaitLogicalIds = Object.getOwnPropertyNames(deleteWaits);
    expect(deleteWaitLogicalIds).toHaveLength(Math.ceil(numDocuments / expectedBatchSize));
  });
});

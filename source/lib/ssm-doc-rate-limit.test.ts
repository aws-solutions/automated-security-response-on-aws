// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnDocument } from 'aws-cdk-lib/aws-ssm';
import { Aspects, CfnCondition, CfnParameter, Fn, Stack } from 'aws-cdk-lib';
import SsmDocRateLimit from './ssm-doc-rate-limit';
import { WaitProvider } from './wait-provider';
import { Template } from 'aws-cdk-lib/assertions';

describe('SSM doc rate limit aspect', function () {
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

  it('matches snapshot', function () {
    expect(template).toMatchSnapshot();
  });

  const documents = template.findResources('AWS::SSM::Document', { Properties: { Content: content } });
  const documentLogicalIds = Object.getOwnPropertyNames(documents);

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

  it('has the correct number of create resources', function () {
    expect(createWaitLogicalIds).toHaveLength(Math.ceil(numDocuments / expectedBatchSize));
  });

  const deleteWaits = template.findResources('Custom::Wait', {
    Properties: {
      CreateIntervalSeconds: 0,
      UpdateIntervalSeconds: 0,
      DeleteIntervalSeconds: 0.5,
      ServiceToken: serviceToken,
    },
  });
  const deleteWaitLogicalIds = Object.getOwnPropertyNames(deleteWaits);

  it('has the correct number of delete resources', function () {
    expect(deleteWaitLogicalIds).toHaveLength(Math.ceil(numDocuments / expectedBatchSize));
  });

  it('create resources form dependency chain', function () {
    expect(formDependencyChain(createWaits)).toStrictEqual(true);
  });

  it('delete resources form dependency chain', function () {
    expect(formDependencyChain(deleteWaits)).toStrictEqual(true);
  });

  it('documents depend on create and delete depends on documents', function () {
    const documentSets: string[][] = [];
    deleteWaitLogicalIds.forEach(function (logicalId: string) {
      documentSets.push(
        (deleteWaits[logicalId].DependsOn as Array<string>).filter(function (value: string) {
          return documentLogicalIds.includes(value);
        }),
      );
    });
    const remainingDocuments = { ...documents };
    documentSets.forEach(function (documentSet: string[]) {
      // all documents depend on the same create resource
      const expectedCreateResource = documents[documentSet[0]].DependsOn[0];
      documentSet.forEach(function (value: string) {
        delete remainingDocuments[value];
        expect(documents[value].DependsOn).toHaveLength(1);
        expect(documents[value].DependsOn[0]).toStrictEqual(expectedCreateResource);
      });
    });
    // all documents in a set
    expect(Object.getOwnPropertyNames(remainingDocuments)).toHaveLength(0);
  });
});

describe('SSM doc rate limit aspect with conditional documents', function () {
  const stack = new Stack();
  const serviceToken = 'my-token';
  const waitProvider = WaitProvider.fromServiceToken(stack, 'WaitProvider', serviceToken);
  Aspects.of(stack).add(new SsmDocRateLimit(waitProvider));
  const content = {};
  const numDocuments = 12;
  for (let i = 0; i < numDocuments; ++i) {
    const param = new CfnParameter(stack, `Parameter${i}`);
    const condition = new CfnCondition(stack, `Condition${i}`, { expression: Fn.conditionEquals(param, 'asdf') });
    const doc = new CfnDocument(stack, `Document${i}`, { content });
    doc.cfnOptions.condition = condition;
  }
  const template = Template.fromStack(stack);

  it('matches snapshot', function () {
    expect(template).toMatchSnapshot();
  });

  const documents = template.findResources('AWS::SSM::Document', { Properties: { Content: content } });
  const documentLogicalIds = Object.getOwnPropertyNames(documents);

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

  it('has the correct number of create resources', function () {
    expect(createWaitLogicalIds).toHaveLength(Math.ceil(numDocuments / expectedBatchSize));
  });

  const deleteWaits = template.findResources('Custom::Wait', {
    Properties: {
      CreateIntervalSeconds: 0,
      UpdateIntervalSeconds: 0,
      DeleteIntervalSeconds: 0.5,
      ServiceToken: serviceToken,
    },
  });
  const deleteWaitLogicalIds = Object.getOwnPropertyNames(deleteWaits);

  it('has the correct number of delete resources', function () {
    expect(deleteWaitLogicalIds).toHaveLength(Math.ceil(numDocuments / expectedBatchSize));
  });

  it('create resources form dependency chain', function () {
    expect(formDependencyChain(createWaits)).toStrictEqual(true);
  });

  it('delete resources form dependency chain', function () {
    expect(formDependencyChain(deleteWaits)).toStrictEqual(true);
  });

  const dummyResources = template.findResources('AWS::CloudFormation::WaitConditionHandle');
  const dummyResourceLogicalIds = Object.getOwnPropertyNames(dummyResources);

  it('documents depend on create and delete depends on documents', function () {
    const documentSets: string[][] = [];
    deleteWaitLogicalIds.forEach(function (logicalId: string) {
      const documentSet: string[] = [];
      const dependencies = deleteWaits[logicalId].DependsOn as Array<string>;
      dependencies.forEach(function (value: string) {
        if (dummyResourceLogicalIds.includes(value)) {
          const dummyResource = dummyResources[value];
          Object.entries(dummyResource.Metadata).forEach(function (meta: [string, unknown]) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            documentSet.push((meta[1] as { [_: string]: any })['Fn::If'][1].Ref);
          });
        }
      });
      documentSet.push(
        ...dependencies.filter(function (value: string) {
          return documentLogicalIds.includes(value);
        }),
      );
      documentSets.push(documentSet);
    });
    const remainingDocuments = { ...documents };
    documentSets.forEach(function (documentSet: string[]) {
      // all documents depend on the same create resource
      const expectedCreateResource = documents[documentSet[0]].DependsOn[0];
      documentSet.forEach(function (value: string) {
        delete remainingDocuments[value];
        expect(documents[value].DependsOn).toHaveLength(1);
        expect(documents[value].DependsOn[0]).toStrictEqual(expectedCreateResource);
      });
    });
    // all documents in a set
    expect(Object.getOwnPropertyNames(remainingDocuments)).toHaveLength(0);
  });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Resources = { [_: string]: { [_: string]: any } };

// do the resources depend on each other in a serial manner
// this isn't foolproof, but it should be enough for simple cases
function formDependencyChain(resources: Resources): boolean {
  const logicalIds = Object.getOwnPropertyNames(resources);
  let dependencyChainFound = false;
  // if so, there will be a resource which starts a chain that contains all the other resources
  logicalIds.forEach(function (logicalId: string | undefined) {
    const resourcesRemaining = { ...resources };
    while (logicalId) {
      let dependencies = resourcesRemaining[logicalId].DependsOn;
      // only check dependencies of the same resource type
      if (dependencies) {
        dependencies = (dependencies as Array<string>).filter(function (value: string) {
          return logicalIds.includes(value);
        });
      }
      delete resourcesRemaining[logicalId];
      if (dependencies && dependencies.length != 0) {
        expect(dependencies).toHaveLength(1);
        logicalId = dependencies[0];
      } else {
        logicalId = undefined;
      }
    }
    // if there are no resources left, this resource is the terminal resource
    if (Object.getOwnPropertyNames(resourcesRemaining).length === 0) {
      dependencyChainFound = true;
    }
  });
  return dependencyChainFound;
}

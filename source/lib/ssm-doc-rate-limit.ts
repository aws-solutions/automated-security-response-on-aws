// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCustomResource, CfnWaitConditionHandle, CustomResource, Fn, IAspect, Stack } from 'aws-cdk-lib';
import { CfnDocument } from 'aws-cdk-lib/aws-ssm';
import { Construct, IConstruct } from 'constructs';
import { createHash, Hash } from 'crypto';
import { WaitProvider } from './wait-provider';

export default class SsmDocRateLimit implements IAspect {
  private readonly waitProvider: WaitProvider;

  private currentCreateWaitResource: CustomResource | undefined;
  private previousCreateWaitResource: CustomResource | undefined;
  private currentDeleteWaitResource: CustomResource | undefined;
  private previousDeleteWaitResource: CustomResource | undefined;
  private currentDummyResource: CfnWaitConditionHandle | undefined;

  private hash: Hash;

  private waitResourceIndex = 0;
  private documentIndex = 0;
  private readonly maxBatchedDocuments = 5;

  constructor(waitProvider: WaitProvider) {
    this.waitProvider = waitProvider;
    this.hash = createHash('sha256');
  }

  private initWaitResources(scope: Construct): void {
    if (!this.currentCreateWaitResource || !this.currentDeleteWaitResource) {
      const resourceIndex = this.waitResourceIndex++;

      this.currentCreateWaitResource = this.waitProvider.createWaitResource(scope, `CreateWait${resourceIndex}`, {
        createIntervalSeconds: 1,
        updateIntervalSeconds: 1,
        deleteIntervalSeconds: 0,
      });

      this.currentDeleteWaitResource = this.waitProvider.createWaitResource(scope, `DeletWait${resourceIndex}`, {
        createIntervalSeconds: 0,
        updateIntervalSeconds: 0,
        deleteIntervalSeconds: 0.5,
      });
    }

    if (this.previousCreateWaitResource) {
      this.currentCreateWaitResource.node.addDependency(this.previousCreateWaitResource);
    }

    if (this.previousDeleteWaitResource) {
      this.currentDeleteWaitResource.node.addDependency(this.previousDeleteWaitResource);
    }
  }

  initDummyResource(scope: Construct): void {
    if (!this.currentDummyResource) {
      this.currentDummyResource = new CfnWaitConditionHandle(scope, `Gate${this.waitResourceIndex - 1}`);
    }
  }

  visit(node: IConstruct): void {
    if (node instanceof CfnDocument) {
      const scope = Stack.of(node);

      this.initWaitResources(scope);
      if (!this.currentCreateWaitResource || !this.currentDeleteWaitResource) {
        throw new Error('Wait resources not initialized');
      }

      this.hash.update(propsStringForDocument(node));
      // multiple calls to digest not allowed, copy to create rolling hash
      const digest = this.hash.copy().digest('hex');
      updateWaitResourceHash(this.currentCreateWaitResource, digest);
      updateWaitResourceHash(this.currentDeleteWaitResource, digest);

      node.addDependency(this.currentCreateWaitResource.node.defaultChild as CfnCustomResource);

      if (node.cfnOptions.condition) {
        this.initDummyResource(scope);
        if (!this.currentDummyResource) {
          throw new Error('Dummy resource not initialized!');
        }
        this.currentDummyResource.addMetadata(
          `${node.logicalId}Ready`,
          Fn.conditionIf(node.cfnOptions.condition.logicalId, Fn.ref(node.logicalId), ''),
        );
        this.currentDeleteWaitResource.node.addDependency(this.currentDummyResource);
      } else {
        this.currentDeleteWaitResource.node.addDependency(node);
      }

      ++this.documentIndex;

      if (this.documentIndex >= this.maxBatchedDocuments) {
        this.documentIndex = 0;
        this.previousCreateWaitResource = this.currentCreateWaitResource;
        this.previousDeleteWaitResource = this.currentDeleteWaitResource;
        this.currentCreateWaitResource = undefined;
        this.currentDeleteWaitResource = undefined;
        this.currentDummyResource = undefined;
        this.hash = createHash('sha256');
      }
    }
  }
}

function propsStringForDocument(document: CfnDocument): string {
  // Changes to this value will result in different hashes for the same resources
  return JSON.stringify([
    document.name,
    document.documentFormat,
    document.documentType,
    document.content,
    document.updateMethod,
  ]);
}

function updateWaitResourceHash(resource: CustomResource, hash: string): void {
  (resource.node.defaultChild as CfnCustomResource).addPropertyOverride('DocumentPropertiesHash', hash);
}

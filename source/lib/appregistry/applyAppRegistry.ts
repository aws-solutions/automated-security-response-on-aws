// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Aspects, Aws, CfnCondition, CfnMapping, Fn, Stack } from 'aws-cdk-lib';
import { Application, AttributeGroup } from '@aws-cdk/aws-servicecatalogappregistry-alpha';
import { applyTag } from '../tags/applyTag';
import {
  CfnAttributeGroup,
  CfnAttributeGroupAssociation,
  CfnResourceAssociation,
} from 'aws-cdk-lib/aws-servicecatalogappregistry';
import { ConditionAspect } from '../cdk-helper/condition-aspect';
import setCondition from '../cdk-helper/set-condition';

export interface AppRegisterProps {
  solutionId: string;
  solutionName: string;
  solutionVersion: string;
  appRegistryApplicationName: string;
  applicationType: string;
}

export class AppRegister {
  private solutionId: string;
  private solutionName: string;
  private solutionVersion: string;
  private appRegistryApplicationName: string;
  private applicationType: string;
  private shouldDeployAppRegCondition?: CfnCondition;

  constructor(props: AppRegisterProps) {
    this.solutionId = props.solutionId;
    this.appRegistryApplicationName = props.appRegistryApplicationName;
    this.solutionName = props.solutionName;
    this.applicationType = props.applicationType;
    this.solutionVersion = props.solutionVersion;
  }

  /**
   * Create AppRegistry Application in hub stack and associate nested stacks.
   *
   * Do not handle spoke stacks. AppRegistry cannot currently handle spoke stacks in different regions.
   * Do not create resource share, it is not needed if spoke accounts are not associated.
   * Do not create ApplicationInsights. This may sometimes fail.
   */
  public applyAppRegistryToStacks(hubStack: Stack, nestedStacks: Stack[]) {
    this.shouldDeployAppRegCondition = new CfnCondition(hubStack, 'ShouldDeployAppReg', {
      expression: Fn.conditionNot(Fn.conditionEquals(Aws.PARTITION, 'aws-cn')),
    });

    const application = this.createAppRegistry(hubStack);
    // Do not create resource share
    // Do not associated spoke stacks, we must allow different regions

    setCondition(application, this.shouldDeployAppRegCondition);
    Aspects.of(application).add(new ConditionAspect(this.shouldDeployAppRegCondition, CfnAttributeGroupAssociation));

    let suffix = 1;
    nestedStacks.forEach((nestedStack) => {
      const association = new CfnResourceAssociation(application, `ResourceAssociation${suffix}`, {
        application: application.applicationId,
        resource: nestedStack.stackId,
        resourceType: 'CFN_STACK',
      });

      association.cfnOptions.condition = nestedStack.nestedStackResource?.cfnOptions.condition;

      if (nestedStack.nestedStackResource) {
        association.addDependency(nestedStack.nestedStackResource);
      } else {
        throw new Error('No nested stack resource');
      }
      suffix++;
    });

    Aspects.of(hubStack).add(new ConditionAspect(this.shouldDeployAppRegCondition, CfnResourceAssociation));
    Aspects.of(hubStack).add(new ConditionAspect(this.shouldDeployAppRegCondition, CfnAttributeGroup));
  }

  private createAppRegistry(stack: Stack): Application {
    const map = this.createMap(stack);

    const application = new Application(stack, 'AppRegistry', {
      applicationName: Fn.join('-', [
        map.findInMap('Data', 'AppRegistryApplicationName'),
        Aws.STACK_NAME,
        Aws.REGION,
        Aws.ACCOUNT_ID,
      ]),
      description: `Service Catalog application to track and manage all your resources for the solution ${this.solutionName}`,
    });
    application.associateApplicationWithStack(stack);

    const attributeGroup = new AttributeGroup(stack, 'DefaultApplicationAttributes', {
      attributeGroupName: 'ASR-' + Aws.STACK_NAME,
      description: 'Attribute group for solution information',
      attributes: {
        applicationType: map.findInMap('Data', 'ApplicationType'),
        version: map.findInMap('Data', 'Version'),
        solutionID: map.findInMap('Data', 'ID'),
        solutionName: map.findInMap('Data', 'SolutionName'),
      },
    });

    application.associateAttributeGroup(attributeGroup);

    // Do not create ApplicationInsights. Creation of the service role may fail.

    this.applyTagsToApplication(application, map);

    return application;
  }

  private createMap(stack: Stack) {
    const map = new CfnMapping(stack, 'Solution');
    map.setValue('Data', 'ID', this.solutionId);
    map.setValue('Data', 'Version', this.solutionVersion);
    map.setValue('Data', 'AppRegistryApplicationName', this.appRegistryApplicationName);
    map.setValue('Data', 'SolutionName', this.solutionName);
    map.setValue('Data', 'ApplicationType', this.applicationType);

    return map;
  }

  private applyTagsToApplication(application: Application, map: CfnMapping) {
    applyTag(application, 'Solutions:SolutionID', map.findInMap('Data', 'ID'));
    applyTag(application, 'Solutions:SolutionName', map.findInMap('Data', 'SolutionName'));
    applyTag(application, 'Solutions:SolutionVersion', map.findInMap('Data', 'Version'));
    applyTag(application, 'Solutions:ApplicationType', map.findInMap('Data', 'ApplicationType'));
  }
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Aspects, Aws, CfnCondition, CfnMapping, Fn, Stack } from 'aws-cdk-lib';
import {
  CfnAttributeGroup,
  CfnAttributeGroupAssociation,
  CfnResourceAssociation,
} from 'aws-cdk-lib/aws-servicecatalogappregistry';
import { Application, AttributeGroup } from '@aws-cdk/aws-servicecatalogappregistry-alpha';
import { ConditionAspect } from '../cdk-helper/condition-aspect';
import setCondition from '../cdk-helper/set-condition';
import { applyTag } from '../tags/applyTag';
import * as appInsights from 'aws-cdk-lib/aws-applicationinsights';

export interface AppRegisterProps {
  solutionId: string;
  solutionName: string;
  solutionVersion: string;
  appRegistryApplicationName: string;
  applicationType: string;
}

export class AppRegister {
  private readonly solutionId: string;
  private readonly solutionName: string;
  private readonly solutionVersion: string;
  private readonly appRegistryApplicationName: string;
  private readonly applicationType: string;

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
   */
  public applyAppRegistry(hubStack: Stack, nestedStacks: Stack[], snsTopicARN: string): void {
    const shouldDeployAppRegCondition = new CfnCondition(hubStack, 'ShouldDeployAppReg', {
      expression: Fn.conditionNot(Fn.conditionEquals(Aws.PARTITION, 'aws-cn')),
    });

    const appRegistryApplication = this.createAppRegistry(hubStack);
    const appInsights = this.createApplicationInsights(
      hubStack,
      appRegistryApplication.applicationName as string,
      snsTopicARN,
    );
    // Do not create resource share
    // Do not associated spoke stacks, we must allow different regions
    Aspects.of(appRegistryApplication).add(
      new ConditionAspect(shouldDeployAppRegCondition, CfnAttributeGroupAssociation),
    );

    let suffix = 1;
    nestedStacks.forEach((nestedStack) => {
      const association = new CfnResourceAssociation(appRegistryApplication, `ResourceAssociation${suffix}`, {
        application: appRegistryApplication.applicationId,
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

    Aspects.of(hubStack).add(new ConditionAspect(shouldDeployAppRegCondition, CfnResourceAssociation));
    Aspects.of(hubStack).add(new ConditionAspect(shouldDeployAppRegCondition, CfnAttributeGroup));

    setCondition(appRegistryApplication, shouldDeployAppRegCondition);
    setCondition(appInsights, shouldDeployAppRegCondition);
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
    this.applyTagsToApplication(application, map);

    return application;
  }

  private createApplicationInsights(
    stack: Stack,
    applicationName: string,
    snsTopicARN: string,
  ): appInsights.CfnApplication {
    return new appInsights.CfnApplication(stack, 'ApplicationInsightsConfiguration', {
      resourceGroupName: Fn.join('-', ['AWS_AppRegistry_Application', applicationName]),
      autoConfigurationEnabled: true,
      cweMonitorEnabled: true,
      opsCenterEnabled: true,
      opsItemSnsTopicArn: snsTopicARN,
    });
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

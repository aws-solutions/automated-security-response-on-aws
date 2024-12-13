#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from "aws-cdk-lib";
import { TestStack } from "../test-stack";

const app = new cdk.App();

const testStack = new TestStack(app, "TestStack", {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({
    generateBootstrapVersionRule: false,
  }),
  description: "Stack containing automated test resources for ASR.",
});
testStack.templateOptions.templateFormatVersion = "2010-09-09";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { getRegexRegistry, RegexTestCase } from './regex_registry';

const testCases: RegexTestCase[] = getRegexRegistry().getAllCases();

test.each(testCases)('%s', (testCase: RegexTestCase) => {
  testCase.runTests();
});

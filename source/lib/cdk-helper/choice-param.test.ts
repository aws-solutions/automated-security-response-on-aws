// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import ChoiceParam from './choice-param';

describe('choice param', function () {
  it('yes has expected value', function () {
    expect(ChoiceParam.Yes).toEqual('yes');
  });

  it('no has expected value', function () {
    expect(ChoiceParam.No).toEqual('no');
  });
});

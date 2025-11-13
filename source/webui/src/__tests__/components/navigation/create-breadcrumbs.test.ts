// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createBreadcrumbs } from '../../../components/navigation/create-breadcrumbs.ts';

it('generates the Home breadcrumb for the empty path', () => {
  // WHEN
  const result = createBreadcrumbs('');

  // THEN
  expect(result).toHaveLength(1);
  expect(result[0]).toEqual({ text: 'Home', href: '/findings' });
});

it('generates breadcrumbs for multiple path elements', () => {
  // WHEN
  const result = createBreadcrumbs('/invite/foo');

  // THEN
  expect(result).toHaveLength(3);
  expect(result[0]).toEqual({ text: 'Home', href: '/findings' });
  expect(result[1]).toEqual({ text: 'Invite', href: '/invite' });
  expect(result[2]).toEqual({ text: 'foo', href: '/invite/foo' });
});

it('uses "Details" as label for uuids', () => {
  // GIVEN
  const findingId = window.crypto.randomUUID();

  // WHEN
  const result = createBreadcrumbs(`/findings/${findingId}`);

  // THEN
  expect(result).toHaveLength(3);
  expect(result[0]).toEqual({ text: 'Home', href: '/findings' });
  expect(result[1]).toEqual({ text: 'Findings', href: '/findings' });
  expect(result[2]).toEqual({ text: 'Details', href: `/findings/${findingId}` });
});

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BreadcrumbGroup, BreadcrumbGroupProps } from '@cloudscape-design/components';
import { useLocation, useNavigate } from 'react-router-dom';
import { createBreadcrumbs } from './create-breadcrumbs.ts';

export const Breadcrumbs = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const path = location.pathname;

  const breadCrumbItems = createBreadcrumbs(path);

  return (
    <BreadcrumbGroup
      onFollow={function (e: CustomEvent) {
        e.preventDefault();
        navigate(e.detail.href);
      }}
      items={breadCrumbItems}
    />
  );
};

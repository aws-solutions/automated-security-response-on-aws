// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// build an array of breadcrumb items, one for each element of the given path
import { BreadcrumbGroupProps } from '@cloudscape-design/components';

export const createBreadcrumbs = (path: string): BreadcrumbGroupProps.Item[] => {
  const pathElements: string[] = path.split('/');

  return pathElements.map((currentElement, index) => {
    const previousPathElementsPlusCurrent = pathElements.slice(0, index + 1);
    let href = `${previousPathElementsPlusCurrent.join('/')}`;
    // Make Home breadcrumb point to /findings
    if (currentElement === '' && index === 0) {
      href = '/findings';
    }

    return { text: getLabelForPathElement(currentElement), href };
  });
};

// Mapping of router path to breadcrumb label
const pathLabels: Record<string, string> = {
  '': 'Home',
  home: 'Home',
  history: 'Execution History',
  findings: 'Findings',
  users: 'View Users',
  invite: 'Invite',
};

function getLabelForPathElement(pathElement: string): string {
  const pathLabel = pathLabels[pathElement];
  if (pathLabel) return pathLabel;

  // 'Details' is supposed to be used for the uuids that are part of the route
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(pathElement)) return 'Details';

  return pathElement;
}

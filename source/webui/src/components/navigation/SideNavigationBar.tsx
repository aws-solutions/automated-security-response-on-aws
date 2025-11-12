// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SideNavigation, SideNavigationProps } from '@cloudscape-design/components';
import { NavigateFunction, useLocation, useNavigate } from 'react-router-dom';
import { useCallback, useContext, useEffect, useState } from 'react';
import { UserContext } from '../../contexts/UserContext.tsx';
import { canAccessUsers } from '../../utils/userPermissions.ts';

export default function SideNavigationBar() {
  const navigate: NavigateFunction = useNavigate();
  const [activeHref, setActiveHref] = useState('/');
  const { groups } = useContext(UserContext);

  const navigationItems: SideNavigationProps['items'] = [
    {
      type: 'section-group',
      title: 'Remediate',
      items: [
        { type: 'link', text: 'Findings', href: '/findings' },
        { type: 'link', text: 'Execution History', href: '/history' },
      ],
    },
    { type: 'divider' },
    ...(canAccessUsers(groups)
      ? [
          {
            type: 'section-group' as const,
            title: 'Access Control',
            items: [
              { type: 'link' as const, text: 'Invite Users', href: '/invite' },
              { type: 'link' as const, text: 'View Users', href: '/users' },
            ],
          },
          { type: 'divider' as const },
        ]
      : []),
    {
      type: 'link',
      external: true,
      href: 'https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/solution-overview.html',
      text: 'Documentation',
    },
  ];

  // follow the given router link and update the store with active path
  const handleFollow = useCallback(
    (event: Readonly<CustomEvent>): void => {
      if (event.detail.external || !event.detail.href) return;

      event.preventDefault();

      const path = event.detail.href;
      navigate(path);
    },
    [navigate],
  );

  const location = useLocation();
  useEffect(() => {
    const pathParts = location.pathname.split('/');
    const topLevelPath = pathParts.length > 1 ? `/${pathParts[1]}` : '/';
    setActiveHref(topLevelPath);
  }, [location]);

  const navHeader: SideNavigationProps.Header = {
    href: '/',
    text: 'Automated Security Response on AWS',
  };

  return <SideNavigation header={navHeader} activeHref={activeHref} onFollow={handleFollow} items={navigationItems} />;
}

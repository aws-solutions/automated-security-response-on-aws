// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Alert, Box, Link, SideNavigation, SideNavigationProps } from '@cloudscape-design/components';
import { NavigateFunction, useLocation, useNavigate } from 'react-router';
import { useCallback, useContext, useEffect, useState } from 'react';
import { UserContext } from '../../contexts/UserContext.tsx';
import { canAccessUsers, canAccessControlPanel } from '../../utils/userPermissions.ts';
import { useVersionCheck, isDismissed, dismissVersionAlert } from './use-version-check.ts';
import { useConfig } from '../../contexts/ConfigContext.tsx';

const canSeeVersionNotification = (groups: string[] | null): boolean => {
  const group = groups?.find((g) => ['AdminGroup', 'DelegatedAdminGroup'].includes(g));
  return group !== undefined;
};

export default function SideNavigationBar() {
  const navigate: NavigateFunction = useNavigate();
  const [activeHref, setActiveHref] = useState('/');
  const { groups } = useContext(UserContext);
  const { solutionVersion } = useConfig();
  const isEligible = canSeeVersionNotification(groups);
  const versionCheck = useVersionCheck(isEligible, solutionVersion);
  const [isVersionDismissed, setIsVersionDismissed] = useState(isDismissed());

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
    ...(canAccessControlPanel(groups)
      ? [
          {
            type: 'section-group' as const,
            title: 'Control Panel',
            items: [
              { type: 'link' as const, text: 'Controls', href: '/controls' },
              { type: 'link' as const, text: 'Resource Filters', href: '/resource-filters' },
              { type: 'link' as const, text: 'Notifications', href: '/notifications' },
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

  const shouldShowVersionAlert = versionCheck && !versionCheck.isNewestVersion && !isVersionDismissed;

  return (
    <>
      <SideNavigation header={navHeader} activeHref={activeHref} onFollow={handleFollow} items={navigationItems} />
      {solutionVersion && (
        <Box padding={{ left: 'xl' }}>
          Version: <strong>{solutionVersion}</strong>
        </Box>
      )}
      {shouldShowVersionAlert && (
        <Box padding="s">
          <Alert
            type="info"
            dismissible={true}
            i18nStrings={{ dismissAriaLabel: 'Dismiss version notification' }}
            onDismiss={() => {
              dismissVersionAlert();
              setIsVersionDismissed(true);
            }}
          >
            A newer version ({versionCheck.latestVersion}) is available.{' '}
            <Link
              external
              href="https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/update-the-solution.html"
            >
              View update instructions
            </Link>{' '}
            <Link external href="https://github.com/aws-solutions/automated-security-response-on-aws/releases/latest">
              View release notes
            </Link>
          </Alert>
        </Box>
      )}
    </>
  );
}

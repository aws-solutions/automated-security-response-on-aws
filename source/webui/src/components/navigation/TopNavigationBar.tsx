// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TopNavigation, TopNavigationProps } from '@cloudscape-design/components';
import { useContext } from 'react';
import { UserContext } from '../../contexts/UserContext.tsx';

export default function TopNavigationBar() {
  const { user, email, signOut } = useContext(UserContext);

  const solutionIdentity: TopNavigationProps.Identity = {
    href: '/',
    logo: { src: '/aws-logo.svg', alt: 'AWS' },
  };

  const i18nStrings: TopNavigationProps.I18nStrings = {
    overflowMenuTitleText: 'All',
    overflowMenuTriggerText: 'More',
  };

  const utilities: TopNavigationProps.Utility[] = [
    {
      type: 'menu-dropdown',
      text: email ?? user?.username ?? 'User',
      iconName: 'user-profile',
      items: [
        {
          id: 'documentation',
          text: 'Documentation',
          href: 'https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/solution-overview.html',
          external: true,
          externalIconAriaLabel: ' (opens in new tab)',
        },
        {
          id: 'signout',
          text: 'Sign Out',
        },
      ],
      onItemClick: async (event) => {
        if (event.detail.id === 'signout') {
          await signOut();
        }
      },
    },
  ];

  return <TopNavigation identity={solutionIdentity} i18nStrings={i18nStrings} utilities={utilities} />;
}

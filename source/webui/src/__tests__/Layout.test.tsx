// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, describe, it, expect } from 'vitest';
import { MemoryRouter } from 'react-router';
import { Provider } from 'react-redux';
import { SplitPanel } from '@cloudscape-design/components';

import Layout from '../Layout.tsx';
import { NotificationContextProvider } from '../contexts/NotificationContext.tsx';
import { setupStore } from '../store/store.ts';
import { SplitPanelProvider, useSplitPanel } from '../contexts/SplitPanelContext.tsx';
import { useEffect } from 'react';

vi.mock('../components/navigation/TopNavigationBar.tsx', () => ({
  default: () => <div data-testid="top-nav-bar">TopNav</div>,
}));

vi.mock('../components/navigation/SideNavigationBar.tsx', () => ({
  default: () => <div>SideNav</div>,
}));

const PanelRegistrar = () => {
  const { registerPanel, openSplitPanel } = useSplitPanel();
  useEffect(() => {
    registerPanel(
      <SplitPanel header="Test Panel" closeBehavior="hide" i18nStrings={{ closeButtonAriaLabel: 'Close panel' }}>
        Panel content
      </SplitPanel>,
    );
    openSplitPanel();
  }, [registerPanel, openSplitPanel]);
  return null;
};

vi.mock('react-router', async () => {
  const actual = await vi.importActual('react-router');
  return {
    ...actual,
    Outlet: () => <PanelRegistrar />,
  };
});

describe('Layout', () => {
  it('closes the split panel when the close button is clicked, even though a child component owns the panel', async () => {
    // ARRANGE
    const store = setupStore();
    render(
      <MemoryRouter>
        <Provider store={store}>
          <NotificationContextProvider>
            <SplitPanelProvider>
              <Layout />
            </SplitPanelProvider>
          </NotificationContextProvider>
        </Provider>
      </MemoryRouter>,
    );

    // ACT
    const closeButton = await screen.findByRole('button', { name: /Close panel/i });
    await userEvent.click(closeButton);

    // ASSERT
    expect(screen.queryByText('Panel content')).not.toBeInTheDocument();
  });
});

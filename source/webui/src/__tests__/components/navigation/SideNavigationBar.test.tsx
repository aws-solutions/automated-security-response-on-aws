// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router';
import SideNavigationBar from '../../../components/navigation/SideNavigationBar.tsx';
import { UserContext } from '../../../contexts/UserContext.tsx';
import { ConfigContextProvider } from '../../../contexts/ConfigContext.tsx';
import { AuthUser } from 'aws-amplify/auth';

const mockGitHubRelease = (tagName: string): Partial<Response> => ({
  ok: true,
  json: () => Promise.resolve({ tag_name: tagName }),
});

const mockUserContext = (groups: string[]) => ({
  user: { userId: 'test', username: 'testuser' } as AuthUser,
  email: 'test@example.com',
  groups,
  signOut: () => Promise.resolve(),
  signInWithRedirect: () => Promise.resolve(),
  checkUser: () => Promise.resolve(),
});

const renderSideNav = (groups: string[]) =>
  render(
    <MemoryRouter>
      <ConfigContextProvider config={{ ticketingEnabled: true, solutionVersion: 'v4.0.0' }}>
        <UserContext.Provider value={mockUserContext(groups)}>
          <SideNavigationBar />
        </UserContext.Provider>
      </ConfigContextProvider>
    </MemoryRouter>,
  );

describe('SideNavigationBar version notification', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('shows current version', () => {
    // GIVEN / WHEN
    renderSideNav(['AdminGroup']);

    // THEN
    expect(screen.getByText('v4.0.0')).toBeInTheDocument();
  });

  it.each(['AdminGroup', 'DelegatedAdminGroup'])(
    'shows version alert for %s when newer version available',
    async (group) => {
      // GIVEN
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v5.0.0') as Response);

      // WHEN
      renderSideNav([group]);

      // THEN
      await waitFor(() => {
        expect(screen.getByText(/A newer version \(v5\.0\.0\) is available/)).toBeInTheDocument();
      });
    },
  );

  it('does not show version alert for AccountOperatorGroup', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v5.0.0') as Response);

    // WHEN
    renderSideNav(['AccountOperatorGroup']);

    // THEN
    await act(async () => {});
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(screen.queryByText(/A newer version/)).not.toBeInTheDocument();
  });

  it('does not show version alert when on latest version', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v4.0.0') as Response);

    // WHEN
    renderSideNav(['AdminGroup']);

    // THEN
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/A newer version/)).not.toBeInTheDocument();
  });

  it('hides version alert after dismissal', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v5.0.0') as Response);
    renderSideNav(['AdminGroup']);

    // WHEN
    const dismissButton = await screen.findByLabelText('Dismiss version notification');
    await userEvent.click(dismissButton);

    // THEN
    expect(screen.queryByText(/A newer version/)).not.toBeInTheDocument();
  });
});

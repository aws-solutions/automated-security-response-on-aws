// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { render } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

import { CallbackPage } from '../../pages/callback/CallbackPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { mockUserContext } from '../test-data-factory.ts';
import { vi } from 'vitest';

const MockHomePage = () => (
  <div>
    <h1>Home Page</h1>
  </div>
);

const renderCallbackPage = (searchParams = '', userContextOverrides = {}) => {
  const contextValue = {
    ...mockUserContext,
    ...userContextOverrides,
  };

  return render(
    <MemoryRouter initialEntries={[`/callback${searchParams}`]}>
      <UserContext.Provider value={contextValue}>
        <Routes>
          <Route path="/callback" element={<CallbackPage />} />
          <Route path="/" element={<MockHomePage />} />
        </Routes>
      </UserContext.Provider>
    </MemoryRouter>,
  );
};

describe('CallbackPage', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('displays error when authentication fails with error parameter', () => {
    // ARRANGE & ACT
    renderCallbackPage('?error=access_denied&error_description=User denied access');

    // ASSERT
    expect(screen.getByRole('heading', { name: 'Automated Security Response on AWS' })).toBeInTheDocument();
    expect(screen.getByText('Sign-in failed')).toBeInTheDocument();
    expect(screen.getByText('User denied access')).toBeInTheDocument();
    expect(
      screen.getByText(/Please ensure you have been invited by an existing Admin or Delegated Admin user/),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try Again' })).toBeInTheDocument();
  });

  it('displays generic error message when only error parameter is present', () => {
    // ARRANGE & ACT
    renderCallbackPage('?error=invalid_request');

    // ASSERT
    expect(screen.getByText('Sign-in failed')).toBeInTheDocument();
    expect(screen.getByText('An authentication error occurred.')).toBeInTheDocument();
  });

  it('displays loading state when no error and user is not authenticated + shows failsafe button after 10 seconds in loading state', () => {
    // ARRANGE & ACT
    vi.useFakeTimers();
    renderCallbackPage('', { user: null });

    // ASSERT
    expect(screen.getByRole('heading', { name: 'Automated Security Response on AWS' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Signing you in...' })).toBeInTheDocument();
    // Initially no failsafe button
    expect(screen.queryByRole('button', { name: 'Continue to Application' })).not.toBeInTheDocument();

    // ACT - Fast-forward 10 seconds
    act(() => {
      vi.advanceTimersByTime(10000);
    });

    // ASSERT - Failsafe button appears
    expect(screen.getByRole('button', { name: 'Continue to Application' })).toBeInTheDocument();
  });

  it('navigates to home when user is authenticated and no error', async () => {
    // ARRANGE & ACT
    renderCallbackPage('', { user: { email: 'test@example.com' } });

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Home Page' })).toBeInTheDocument();
    });
  });

  it('handles try again button click', async () => {
    // ARRANGE
    renderCallbackPage('?error=access_denied');

    // ACT
    const tryAgainButton = screen.getByRole('button', { name: 'Try Again' });
    await userEvent.click(tryAgainButton);

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Home Page' })).toBeInTheDocument();
    });
  });

  it('handles continue to application button click', async () => {
    // ARRANGE
    vi.useFakeTimers();
    renderCallbackPage('', { user: null });
    act(() => {
      vi.advanceTimersByTime(10000);
    });
    vi.useRealTimers();

    // ACT
    const continueButton = screen.getByRole('button', { name: 'Continue to Application' });
    await userEvent.click(continueButton);

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Home Page' })).toBeInTheDocument();
    });
  });

  it('redirects to base page when user is authenticated', async () => {
    // ARRANGE & ACT
    renderCallbackPage('', { user: { email: 'test@example.com' } });

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Home Page' })).toBeInTheDocument();
    });
  });
});

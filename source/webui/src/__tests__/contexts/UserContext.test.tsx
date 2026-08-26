// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import {
  AuthUser,
  fetchUserAttributes,
  getCurrentUser,
  signInWithRedirect,
  signOut,
  fetchAuthSession,
} from 'aws-amplify/auth';
import { Hub } from 'aws-amplify/utils';

import { UserContext, UserContextProvider } from '../../contexts/UserContext.tsx';
import { rootReducer } from '../../store/store.ts';
import { solutionApi } from '../../store/solutionApi.ts';
import { useContext } from 'react';
import { AUTH_REDIRECT_DESTINATION_KEY } from '../../utils/constants.ts';

// Mock AWS Amplify
vi.mock('aws-amplify/auth', () => ({
  getCurrentUser: vi.fn(),
  fetchUserAttributes: vi.fn(),
  fetchAuthSession: vi.fn(),
  signOut: vi.fn(),
  signInWithRedirect: vi.fn(),
}));

vi.mock('aws-amplify/utils', () => ({
  Hub: {
    listen: vi.fn(),
  },
}));

const mockGetCurrentUser = vi.mocked(getCurrentUser);
const mockFetchUserAttributes = vi.mocked(fetchUserAttributes);
const mockFetchAuthSession = vi.mocked(fetchAuthSession);
const mockSignOut = vi.mocked(signOut);
const mockSignInWithRedirect = vi.mocked(signInWithRedirect);
const mockHubListen = vi.mocked(Hub.listen);

const mockUser: AuthUser = {
  username: 'testuser',
  userId: 'test-user-id',
} as AuthUser;

const TestComponent = () => {
  const context = useContext(UserContext);
  return (
    <div>
      <div data-testid="user">{context.user?.username || 'null'}</div>
      <div data-testid="email">{context.email || 'null'}</div>
      <div data-testid="groups">{context.groups?.join(',') || 'null'}</div>
      <button onClick={() => context.signOut()} data-testid="signOut">
        Sign Out
      </button>
      <button onClick={() => context.signInWithRedirect()} data-testid="signIn">
        Sign In
      </button>
    </div>
  );
};

const renderWithProvider = () => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  return render(
    <Provider store={store}>
      <UserContextProvider>
        <TestComponent />
      </UserContextProvider>
    </Provider>,
  );
};

const originalLocation = window.location;

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  Object.defineProperty(window, 'location', { value: originalLocation, writable: true });
});

describe('UserContext', () => {
  it('initializes with default values', () => {
    // ARRANGE
    mockGetCurrentUser.mockRejectedValue(new Error('Not authenticated'));

    // ACT
    renderWithProvider();

    // ASSERT
    expect(screen.getByTestId('user')).toHaveTextContent('null');
    expect(screen.getByTestId('email')).toHaveTextContent('null');
    expect(screen.getByTestId('groups')).toHaveTextContent('null');
  });

  it('loads user successfully and fetches groups', async () => {
    // ARRANGE
    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup', 'DelegatedAdminGroup'],
          },
        },
      },
    } as any);

    // ACT
    renderWithProvider();

    // ASSERT
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });

    await waitFor(() => {
      expect(screen.getByTestId('email')).toHaveTextContent('test@example.com');
    });

    await waitFor(() => {
      expect(screen.getByTestId('groups')).toHaveTextContent('AdminGroup,DelegatedAdminGroup');
    });
  });

  it('handles getCurrentUser failure and triggers sign in redirect', async () => {
    // ARRANGE
    mockGetCurrentUser.mockRejectedValue(new Error('Not authenticated'));
    mockSignInWithRedirect.mockResolvedValue();

    // ACT
    renderWithProvider();

    // ASSERT
    await waitFor(() => {
      expect(mockSignInWithRedirect).toHaveBeenCalled();
    });

    expect(screen.getByTestId('user')).toHaveTextContent('null');
  });

  it('stores intended destination in sessionStorage before redirect when on a non-root path', async () => {
    // ARRANGE
    mockGetCurrentUser.mockRejectedValue(new Error('Not authenticated'));
    mockSignInWithRedirect.mockResolvedValue();
    const setItemSpy = vi.spyOn(Storage.prototype, 'setItem');
    Object.defineProperty(window, 'location', {
      value: { pathname: '/controls', search: '?controlId=S3.1', hash: '' },
      writable: true,
    });

    // ACT
    renderWithProvider();

    // ASSERT
    await waitFor(() => {
      expect(setItemSpy).toHaveBeenCalledWith(AUTH_REDIRECT_DESTINATION_KEY, '/controls?controlId=S3.1');
    });

    setItemSpy.mockRestore();
  });

  it('does not store destination in sessionStorage when on root path', async () => {
    // ARRANGE
    mockGetCurrentUser.mockRejectedValue(new Error('Not authenticated'));
    mockSignInWithRedirect.mockResolvedValue();
    const setItemSpy = vi.spyOn(Storage.prototype, 'setItem');
    Object.defineProperty(window, 'location', {
      value: { pathname: '/', search: '', hash: '' },
      writable: true,
    });

    // ACT
    renderWithProvider();

    // ASSERT
    await waitFor(() => {
      expect(mockSignInWithRedirect).toHaveBeenCalled();
    });
    expect(setItemSpy).not.toHaveBeenCalledWith(AUTH_REDIRECT_DESTINATION_KEY, expect.anything());

    setItemSpy.mockRestore();
  });

  it('handles fetchUserAttributes failure gracefully', async () => {
    // ARRANGE
    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockRejectedValue(new Error('Failed to fetch attributes'));

    // ACT
    renderWithProvider();

    // ASSERT - user is still set despite fetchUserAttributes failure
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });
    // groups should be set to empty array as fallback when inner try block fails
    await waitFor(() => {
      expect(screen.getByTestId('groups')).toHaveTextContent('null');
    });
    expect(screen.getByTestId('email')).toHaveTextContent('null');
  });

  it('handles sign in redirect failure gracefully', async () => {
    // ARRANGE
    mockGetCurrentUser.mockRejectedValue(new Error('Not authenticated'));
    mockSignInWithRedirect.mockRejectedValue(new Error('Sign in failed'));

    // ACT
    renderWithProvider();

    // ASSERT - signInWithRedirect was attempted despite failure
    await waitFor(() => {
      expect(mockSignInWithRedirect).toHaveBeenCalled();
    });
    // User remains null after failed sign in attempt
    expect(screen.getByTestId('user')).toHaveTextContent('null');
  });

  it('calls signOut function correctly', async () => {
    // ARRANGE
    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup'],
          },
        },
      },
    } as any);
    mockSignOut.mockResolvedValue();

    // ACT
    renderWithProvider();

    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });

    const signOutButton = screen.getByTestId('signOut');
    signOutButton.click();

    // ASSERT
    expect(mockSignOut).toHaveBeenCalled();
  });

  it('calls signInWithRedirect function correctly', async () => {
    // ARRANGE
    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup'],
          },
        },
      },
    } as any);
    mockSignInWithRedirect.mockResolvedValue();

    // ACT
    renderWithProvider();

    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });

    const signInButton = screen.getByTestId('signIn');
    signInButton.click();

    // ASSERT
    expect(mockSignInWithRedirect).toHaveBeenCalled();
  });

  it('handles Hub auth events correctly', async () => {
    // ARRANGE
    let hubCallback: ((data: any) => void) | null = null;
    // @ts-ignore - mock implementation
    mockHubListen.mockImplementation((channel, callback) => {
      if (channel === 'auth') {
        hubCallback = callback;
      }
    });

    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup'],
          },
        },
      },
    } as any);

    // ACT
    renderWithProvider();

    // Wait for initial load
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });

    // Simulate signedOut event
    await act(async () => {
      if (hubCallback) {
        hubCallback({ payload: { event: 'signedOut' } });
      }
    });

    // ASSERT
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('null');
    });
  });

  it('handles signInWithRedirect Hub event', async () => {
    // ARRANGE
    let hubCallback: ((data: any) => void) | null = null;
    // @ts-ignore - mock implementation
    mockHubListen.mockImplementation((channel, callback) => {
      if (channel === 'auth') {
        hubCallback = callback;
      }
    });

    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup'],
          },
        },
      },
    } as any);

    // ACT
    renderWithProvider();

    // Simulate signInWithRedirect event
    await act(async () => {
      if (hubCallback) {
        hubCallback({ payload: { event: 'signInWithRedirect' } });
      }
    });

    // ASSERT
    await waitFor(() => {
      expect(mockGetCurrentUser).toHaveBeenCalled();
    });
  });

  it('handles unknown Hub events gracefully', async () => {
    // ARRANGE
    let hubCallback: ((data: any) => void) | null = null;
    // @ts-ignore - mock implementation
    mockHubListen.mockImplementation((channel, callback) => {
      if (channel === 'auth') {
        hubCallback = callback;
      }
    });

    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup'],
          },
        },
      },
    } as any);

    // ACT
    renderWithProvider();

    // Simulate unknown event
    await act(async () => {
      if (hubCallback) {
        hubCallback({ payload: { event: 'unknownEvent' } });
      }
    });

    // ASSERT - Should not crash or change state
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });
  });

  it('handles fetchAuthSession with no groups', async () => {
    // ARRANGE
    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({ email: 'test@example.com' });
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {},
        },
      },
    } as any);

    // ACT
    renderWithProvider();

    // ASSERT
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });

    await waitFor(() => {
      expect(screen.getByTestId('email')).toHaveTextContent('test@example.com');
    });

    expect(screen.getByTestId('groups')).toHaveTextContent('null');
  });

  it('handles missing email in user attributes', async () => {
    // ARRANGE
    mockGetCurrentUser.mockResolvedValue(mockUser);
    mockFetchUserAttributes.mockResolvedValue({});
    mockFetchAuthSession.mockResolvedValue({
      tokens: {
        accessToken: {
          payload: {
            'cognito:groups': ['AdminGroup'],
          },
        },
      },
    } as any);

    // ACT
    renderWithProvider();

    // ASSERT
    await waitFor(() => {
      expect(screen.getByTestId('user')).toHaveTextContent('testuser');
    });

    expect(screen.getByTestId('email')).toHaveTextContent('null');
  });
});

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useContext, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Container, Header, Alert, Spinner, Button, SpaceBetween, Box } from '@cloudscape-design/components';
import { UserContext } from '../../contexts/UserContext.tsx';

const SolutionHeader = () => <Header variant="h1">Automated Security Response on AWS</Header>;

export const CallbackPage = () => {
  const { user, checkUser } = useContext(UserContext);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const error = searchParams.get('error');
  const errorDescription = searchParams.get('error_description');
  const [showFailsafe, setShowFailsafe] = useState(false);

  useEffect(() => {
    // Wait for Amplify to process the authorization code before checking user
    if (!error && !errorDescription) {
      // Give Amplify time to process the authorization code
      const timer = setTimeout(() => {
        checkUser();
      }, 1000);
      
      return () => clearTimeout(timer);
    }
  }, [checkUser, error, errorDescription]);

  useEffect(() => {
    // If user is authenticated and no error, redirect to home
    if (user && !error) {
      navigate('/');
    }
  }, [user, error, navigate]);

  useEffect(() => {
    // Show failsafe redirect button after 10 seconds if no error is present
    if (!error && !errorDescription) {
      const timer = setTimeout(() => setShowFailsafe(true), 10000);
      return () => clearTimeout(timer);
    }
  }, [error, errorDescription]);

  if (error || errorDescription) {
    return (
      <Box padding="xxl">
        <Container>
          <SpaceBetween direction="vertical" size="l">
            <SolutionHeader />
            <Alert type="error" header="Sign-in failed">
              {errorDescription || 'An authentication error occurred.'}
            </Alert>
            <Alert type="info" header="Note">
              Please ensure you have been invited by an existing Admin or Delegated Admin user, and you are logging-in
              with the same email address where you received the invitation.
            </Alert>
            <Button
              variant="primary"
              onClick={() => {
                navigate('/');
                checkUser();
              }}
            >
              Try Again
            </Button>
          </SpaceBetween>
        </Container>
      </Box>
    );
  }

  if (!user) {
    return (
      <Box padding="xxl">
        <Container>
          <SpaceBetween direction="vertical" size="l">
            <SolutionHeader />
            <Header variant="h2">Signing you in...</Header>
            <Spinner size="large" />
            {showFailsafe && (
              <Button
                variant="normal"
                onClick={() => {
                  navigate('/');
                  checkUser();
                }}
              >
                Continue to Application
              </Button>
            )}
          </SpaceBetween>
        </Container>
      </Box>
    );
  }

  return null;
};

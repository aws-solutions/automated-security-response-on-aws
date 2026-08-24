// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ReadOnlyBadge } from '../../components/ReadOnlyBadge.tsx';

describe('ReadOnlyBadge', () => {
  it('renders nothing when visible is false', () => {
    // ARRANGE / ACT
    const { container } = render(<ReadOnlyBadge visible={false} />);

    // ASSERT
    expect(container).toBeEmptyDOMElement();
  });

  it('renders the badge when visible is true', () => {
    // ARRANGE / ACT
    render(<ReadOnlyBadge visible={true} />);

    // ASSERT
    expect(screen.getByText('Read-only')).toBeInTheDocument();
  });

  it('shows popover with explanation on click', async () => {
    // ARRANGE
    const user = userEvent.setup();
    render(<ReadOnlyBadge visible={true} />);

    // ACT
    const badge = screen.getByText('Read-only');
    await user.click(badge);

    // ASSERT
    expect(await screen.findByText(/read-only access/i)).toBeInTheDocument();
    expect(await screen.findByText(/contact an administrator/i)).toBeInTheDocument();
  });
});

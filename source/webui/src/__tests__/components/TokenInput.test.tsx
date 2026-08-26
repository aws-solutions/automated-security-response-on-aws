// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, describe, it, expect } from 'vitest';

import { TokenInput } from '../../components/TokenInput.tsx';
import { useTokenListField } from '../../hooks/useTokenListField.ts';

const noopValidate = () => null;
const rejectValidate = (value: string) => (value === 'bad' ? 'Invalid value' : null);

const TokenInputHarness = ({ validate = noopValidate }: { validate?: (v: string) => string | null }) => {
  const field = useTokenListField({ validate });
  return (
    <TokenInput
      value={field.input}
      onChange={field.setInput}
      tokens={field.tokens}
      onAddToken={field.addToken}
      onRemoveToken={field.removeToken}
      ariaLabel="Account IDs"
      placeholder="Enter an account ID"
    />
  );
};

const defaultProps = () => ({
  value: '',
  onChange: vi.fn(),
  tokens: [] as string[],
  onAddToken: vi.fn(),
  onRemoveToken: vi.fn(),
  ariaLabel: 'Account IDs',
  placeholder: 'Enter an account ID',
});

describe('TokenInput', () => {
  it('renders the input with placeholder and does not render TokenGroup when tokens are empty', () => {
    // ARRANGE & ACT
    render(<TokenInput {...defaultProps()} />);

    // ASSERT
    expect(screen.getByPlaceholderText('Enter an account ID')).toBeInTheDocument();
    expect(screen.getByLabelText('Account IDs')).toBeInTheDocument();
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('renders tokens and calls onRemoveToken when a token is dismissed', async () => {
    // ARRANGE
    const props = defaultProps();
    props.tokens = ['111111111111', '222222222222'];
    render(<TokenInput {...props} />);

    // ACT
    expect(screen.getByText('111111111111')).toBeInTheDocument();
    expect(screen.getByText('222222222222')).toBeInTheDocument();
    const dismissButton = screen.getByRole('button', { name: 'Remove 111111111111' });
    await userEvent.click(dismissButton);

    // ASSERT
    expect(props.onRemoveToken).toHaveBeenCalledWith(0);
  });

  it('calls onChange when the user types and onAddToken when Enter is pressed', async () => {
    // ARRANGE
    const props = defaultProps();
    render(<TokenInput {...props} />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, 'abc');

    // ASSERT
    expect(props.onChange).toHaveBeenCalled();
    const lastCall = props.onChange.mock.calls[props.onChange.mock.calls.length - 1];
    expect(lastCall[0]).toBe('c');

    // ACT - press Enter
    await userEvent.keyboard('{Enter}');

    // ASSERT
    expect(props.onAddToken).toHaveBeenCalled();
  });

  it('does not call onAddToken for non-Enter keys', async () => {
    // ARRANGE
    const props = defaultProps();
    render(<TokenInput {...props} />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, 'x');

    // ASSERT
    expect(props.onAddToken).not.toHaveBeenCalled();
  });

  it('disables the input when disabled prop is true', () => {
    // ARRANGE
    const props = { ...defaultProps(), disabled: true };

    // ACT
    render(<TokenInput {...props} />);

    // ASSERT
    const input = screen.getByLabelText('Account IDs');
    expect(input).toBeDisabled();
  });
});

describe('TokenInput + useTokenListField integration', () => {
  it('adds a token visually when the user types a value and presses Enter', async () => {
    // ARRANGE
    render(<TokenInputHarness />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, '111111111111{Enter}');

    // ASSERT
    expect(screen.getByText('111111111111')).toBeInTheDocument();
    expect(input).toHaveValue('');
  });

  it('adds multiple tokens and displays all of them', async () => {
    // ARRANGE
    render(<TokenInputHarness />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, 'token-a{Enter}');
    await userEvent.type(input, 'token-b{Enter}');

    // ASSERT
    expect(screen.getByText('token-a')).toBeInTheDocument();
    expect(screen.getByText('token-b')).toBeInTheDocument();
  });

  it('removes a token from the visible list when dismissed', async () => {
    // ARRANGE
    render(<TokenInputHarness />);
    const input = screen.getByLabelText('Account IDs');
    await userEvent.type(input, 'first{Enter}');
    await userEvent.type(input, 'second{Enter}');

    // ACT
    const dismissButton = screen.getByRole('button', { name: 'Remove first' });
    await userEvent.click(dismissButton);

    // ASSERT
    expect(screen.queryByText('first')).not.toBeInTheDocument();
    expect(screen.getByText('second')).toBeInTheDocument();
  });

  it('does not add a duplicate token', async () => {
    // ARRANGE
    render(<TokenInputHarness />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, 'same{Enter}');
    await userEvent.type(input, 'same{Enter}');

    // ASSERT
    const matches = screen.getAllByText('same');
    expect(matches).toHaveLength(1);
  });

  it('does not add a token when the input is empty or whitespace', async () => {
    // ARRANGE
    render(<TokenInputHarness />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, '   {Enter}');

    // ASSERT
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
    await waitFor(() => expect(input).toHaveValue(''));
  });

  it('does not add a token that fails validation', async () => {
    // ARRANGE
    render(<TokenInputHarness validate={rejectValidate} />);
    const input = screen.getByLabelText('Account IDs');

    // ACT
    await userEvent.type(input, 'bad{Enter}');

    // ASSERT
    expect(screen.queryByText('bad')).not.toBeInTheDocument();
    expect(input).toHaveValue('bad');
  });
});

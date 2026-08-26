// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import FormField from '@cloudscape-design/components/form-field';
import { TokenInput } from './TokenInput.tsx';

interface TokenListFieldState {
  input: string;
  setInput: (value: string) => void;
  tokens: string[];
  error: string | undefined;
  addToken: () => void;
  removeToken: (index: number) => void;
}

interface TokenFormFieldProps {
  field: TokenListFieldState;
  label: string;
  description: string;
  placeholder: string;
  ariaLabel: string;
  disabled?: boolean;
}

export const TokenFormField = ({
  field,
  label,
  description,
  placeholder,
  ariaLabel,
  disabled = false,
}: TokenFormFieldProps): React.JSX.Element => (
  <FormField label={label} description={description} errorText={field.error}>
    <TokenInput
      value={field.input}
      onChange={field.setInput}
      tokens={field.tokens}
      onAddToken={field.addToken}
      onRemoveToken={field.removeToken}
      ariaLabel={ariaLabel}
      placeholder={placeholder}
      disabled={disabled}
    />
  </FormField>
);

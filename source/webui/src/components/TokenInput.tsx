// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import Input from '@cloudscape-design/components/input';
import TokenGroup from '@cloudscape-design/components/token-group';
import SpaceBetween from '@cloudscape-design/components/space-between';

interface TokenInputProps {
  value: string;
  onChange: (value: string) => void;
  tokens: string[];
  onAddToken: () => void;
  onRemoveToken: (index: number) => void;
  ariaLabel: string;
  placeholder: string;
  disabled?: boolean;
}

/**
 * A text input paired with a Cloudscape TokenGroup for managing a list of string values.
 * Users type a value and press Enter to add it as a Token (a dismissible tag chip rendered
 * by Cloudscape's TokenGroup component). Existing tokens are displayed below the input
 * and can be individually removed.
 *
 * This is a custom component because Cloudscape doesn't offer a built-in free-form
 * token entry field. PropertyFilter is the closest native option but is designed for
 * structured property/operator/value queries tied to collection filtering, not for
 * collecting arbitrary string lists (account IDs, OU paths, ARN patterns, etc.).
 */
export const TokenInput = ({
  value,
  onChange,
  tokens,
  onAddToken,
  onRemoveToken,
  ariaLabel,
  placeholder,
  disabled = false,
}: TokenInputProps) => (
  <SpaceBetween size="xs">
    <Input
      value={value}
      onChange={({ detail }) => onChange(detail.value)}
      onKeyDown={({ detail }) => {
        if (detail.key === 'Enter') onAddToken();
      }}
      onBlur={onAddToken}
      placeholder={placeholder}
      ariaLabel={ariaLabel}
      disabled={disabled}
    />
    {tokens.length > 0 && (
      <TokenGroup
        items={tokens.map((token) => ({ label: token, dismissLabel: `Remove ${token}` }))}
        onDismiss={({ detail }) => onRemoveToken(detail.itemIndex)}
      />
    )}
  </SpaceBetween>
);

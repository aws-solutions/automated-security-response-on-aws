// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';

interface UseTokenListFieldParams {
  initialTokens?: string[];
  validate: (value: string) => string | null;
}

interface UseTokenListFieldResult {
  input: string;
  setInput: (value: string) => void;
  tokens: string[];
  setTokens: (tokens: string[]) => void;
  error: string | undefined;
  addToken: () => void;
  removeToken: (index: number) => void;
  reset: (tokens?: string[]) => void;
}

export function useTokenListField({ initialTokens = [], validate }: UseTokenListFieldParams): UseTokenListFieldResult {
  const [input, setInput] = useState('');
  const [tokens, setTokens] = useState<string[]>(initialTokens);
  const [error, setError] = useState<string | undefined>(undefined);

  const addToken = useCallback(() => {
    const trimmed = input.trim();
    if (!trimmed) {
      setInput('');
      return;
    }

    const validationError = validate(trimmed);
    if (validationError) {
      setError(validationError);
      return;
    }

    setTokens((prev) => {
      if (prev.includes(trimmed)) return prev;
      return [...prev, trimmed];
    });
    setInput('');
    setError(undefined);
  }, [input, validate]);

  const removeToken = useCallback((index: number) => {
    setTokens((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const reset = useCallback((resetTokens: string[] = []) => {
    setInput('');
    setTokens(resetTokens);
    setError(undefined);
  }, []);

  return { input, setInput, tokens, setTokens, error, addToken, removeToken, reset };
}

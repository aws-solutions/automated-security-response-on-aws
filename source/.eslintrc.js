// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
module.exports = {
  env: {
    jest: true,
    node: true,
  },
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended', 'plugin:prettier/recommended'],
  ignorePatterns: ['node_modules', '**/*.d.ts', '**/*.js', '**/vite.config.ts'],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    project: ['./tsconfig.json', './webui/tsconfig.json', './lambdas/tsconfig.json', './playbooks/*/tsconfig.json'],
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint', 'header', 'import'],
  root: true,
  rules: {
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-unused-vars': 'off',
    '@typescript-eslint/ban-ts-comment': 'off',
    '@typescript-eslint/no-empty-function': 'off',
    '@typescript-eslint/no-empty-object-type': 'off',
    // treat prettier as warning rather than error. prettier can be used as formatter, but should not fail the build
    'prettier/prettier': 'warn',
    'header/header': [
      'error',
      'line',
      [' Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.', ' SPDX-License-Identifier: Apache-2.0'],
      1,
    ],
  },
};

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
module.exports = {
  "env": {
    "jest": true,
    "node": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:prettier/recommended"
  ],
  "ignorePatterns": [
    "node_modules",
    "**/*.d.ts",
    "**/*.js"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": "latest",
    "project": "**/tsconfig.json",
    "sourceType": "module"
  },
  "plugins": [
    "@typescript-eslint",
    "header",
    "import"
  ],
  "root": true,
  "rules": {
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/no-unused-vars": "off",
    "header/header": [
      "error",
      "line",
      [
        " Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
        " SPDX-License-Identifier: Apache-2.0"
      ],
      1
    ]
  }
};

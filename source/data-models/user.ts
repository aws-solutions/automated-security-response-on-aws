// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { z } from 'zod';

// Account IDs validation schema
export const accountIdsSchema = z.array(z.string().regex(/^\d{12}$/)).min(1);

// User type constants
export const USER_TYPE_ACCOUNT_OPERATOR = 'account-operator' as const;
export const USER_TYPE_DELEGATED_ADMIN = 'delegated-admin' as const;
export const USER_TYPE_ADMIN = 'admin' as const;

// Base user schema
export const GeneralUserSchema = z.object({
  email: z.string().email(),
  invitedBy: z.union([z.string().email(), z.literal('system')]),
  invitationTimestamp: z.string().datetime(),
  status: z.enum(['Invited', 'Confirmed']),
  type: z.string(),
  /**
   * MCP tools explicitly granted to a Delegated Admin or Account Operator.
   * AdminGroup receives every tool automatically, so this field is absent.
   * For grant-managed roles, missing and empty both mean no MCP access.
   */
  allowedMcpTools: z.array(z.string()).optional(),
});

// Specific user type schemas
export const AccountOperatorUserSchema = GeneralUserSchema.extend({
  accountIds: accountIdsSchema,
  type: z.literal(USER_TYPE_ACCOUNT_OPERATOR),
});

export const DelegatedAdminUserSchema = GeneralUserSchema.extend({
  type: z.literal(USER_TYPE_DELEGATED_ADMIN),
});

export const AdminUserSchema = GeneralUserSchema.extend({
  type: z.literal(USER_TYPE_ADMIN),
});

// User account mapping schema (from lambda)
//
// `accountIds`, `invitedBy`, and `invitationTimestamp` are optional because this
// table holds two record shapes keyed by user email: a full mapping written when an
// Account Operator is invited (with assigned accounts and invite provenance), and a
// grant-only record created when an admin grants MCP tools to a Delegated Admin —
// who legitimately has no assigned accounts and whose row is upserted by the tool
// grant alone. A reader that needs assigned accounts must treat their absence as
// "no accounts" rather than assume the field is present.
export const UserAccountMappingSchema = z.object({
  userId: z.string().email(),
  accountIds: accountIdsSchema.optional(),
  allowedMcpTools: z.array(z.string()).optional(),
  invitedBy: z.union([z.string().email(), z.literal('system')]).optional(),
  invitationTimestamp: z.string().datetime().optional(),
  lastModifiedBy: z.string().email().optional(),
  lastModifiedTimestamp: z.string().datetime().optional(),
});

// Request body for replacing a user's MCP tool grant. Empty revokes all tools.
export const PutUserMcpToolsRequestSchema = z
  .object({
    allowedTools: z.array(z.string().min(1)),
  })
  .strict();
export type PutUserMcpToolsRequest = z.infer<typeof PutUserMcpToolsRequestSchema>;

// Request schemas
export const InviteUserRequest = z
  .object({
    accountIds: accountIdsSchema.optional(),
    role: z.enum(['AccountOperator', 'DelegatedAdmin']),
    email: z.string().email(),
  })
  .strict();

export const PutUserRequest = z
  .object({
    type: z.string(), // Required for business logic validation
    accountIds: accountIdsSchema, // Required in API calls
    email: z.string().email(),
    status: z.enum(['Invited', 'Confirmed']).optional(),
  })
  .strict();

// Type exports
export type DelegatedAdminUser = z.infer<typeof DelegatedAdminUserSchema>;
export type AccountOperatorUser = z.infer<typeof AccountOperatorUserSchema>;
export type AdminUser = z.infer<typeof AdminUserSchema>;
export type UserAccountMapping = z.infer<typeof UserAccountMappingSchema>;
export type userAccountIds = z.infer<typeof accountIdsSchema>;
export type User = DelegatedAdminUser | AccountOperatorUser | AdminUser;
export type InviteUserRequest = z.infer<typeof InviteUserRequest>;
export type PutUserRequest = z.infer<typeof PutUserRequest>;

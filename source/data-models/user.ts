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
export const UserAccountMappingSchema = z.object({
  userId: z.string().email(),
  accountIds: accountIdsSchema,
  invitedBy: z.union([z.string().email(), z.literal('system')]),
  invitationTimestamp: z.string().datetime(),
  lastModifiedBy: z.string().email().optional(),
  lastModifiedTimestamp: z.string().datetime().optional(),
});

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

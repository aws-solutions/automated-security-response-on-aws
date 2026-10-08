// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { User } from '@asr/data-models';
import { BadRequestError } from '../../common/utils/httpErrors';
import {
  ACCOUNT_OPERATOR_TOOLS,
  ADMIN_TOOLS,
  ToolCategory,
  categoryForTool,
  matchesToolPattern,
} from '../../mcp-server/contract/toolContract';
import { CognitoService } from './cognito';

/**
 * One tool in the grantable-tool catalog: the lowest tier that can be granted it and
 * the category the Web UI groups it under. The category is presentation only — it
 * carries no authorization meaning.
 */
export interface GrantableTool {
  readonly name: string;
  readonly tier: 'AccountOperator' | 'DelegatedAdmin';
  readonly category: ToolCategory;
}

export interface McpToolGrantResult {
  readonly email: string;
  readonly allowedMcpTools: readonly string[];
}

/**
 * Business logic for per-user MCP tool grants (ADR 0003 Handler→Service→Repository).
 *
 * The handler owns only HTTP concerns — authorization, request parsing, response
 * shaping. The rules for WHICH tools a user may be granted, how grant patterns are
 * validated against a role's ceiling, and the persistence call live here so they are
 * testable in isolation and not entangled with the handler. Persistence goes through
 * CognitoService (which owns the Cognito + mapping-table writes); this service never
 * touches an AWS client directly.
 */
export class McpToolGrantService {
  constructor(
    private readonly cognitoService: CognitoService,
    private readonly logger: Logger,
  ) {}

  /**
   * The catalog of grantable tools with the lowest tier each is available to and the
   * category it is grouped under. ADMIN_TOOLS is the widest set; a tool also in
   * ACCOUNT_OPERATOR_TOOLS is grantable down to that tier, everything else only to
   * DelegatedAdmin.
   */
  listGrantableTools(): readonly GrantableTool[] {
    const accountOperatorTools = new Set(ACCOUNT_OPERATOR_TOOLS);
    return ADMIN_TOOLS.map((name) => ({
      name,
      tier: accountOperatorTools.has(name) ? 'AccountOperator' : 'DelegatedAdmin',
      category: categoryForTool(name),
    }));
  }

  /**
   * Validate and store a user's MCP tool grant.
   *
   * `userId` is the write key — the path id verbatim, matching putUser/deleteUser —
   * because the Cognito pool is case-sensitive and createUser stores the email as
   * given, so lower-casing here could miss a mixed-case user. The response reports
   * the canonical `targetUser.email`.
   *
   * AdminGroup receives every tool automatically, so a stored grant for an Admin is
   * rejected rather than silently ignored. For a Delegated Admin or Account Operator,
   * each requested entry must match — by exact name or a supported wildcard pattern —
   * at least one tool grantable to that role; an entry that reaches outside the role
   * (e.g. `deploy_*` for an Account Operator) or is a typo matches nothing and is
   * rejected. The grant that reaches storage is thus bounded to the role's ceiling.
   */
  async grantTools(
    userId: string,
    targetUser: User,
    allowedTools: readonly string[],
    actorEmail: string,
  ): Promise<McpToolGrantResult> {
    if (targetUser.type === 'admin') {
      throw new BadRequestError('AdminGroup receives all MCP tools automatically and does not accept a tool grant.');
    }

    const grantableTools = targetUser.type === 'account-operator' ? ACCOUNT_OPERATOR_TOOLS : ADMIN_TOOLS;
    const invalidPatterns = allowedTools.filter(
      (pattern) => !grantableTools.some((toolName) => matchesToolPattern(toolName, pattern)),
    );
    if (invalidPatterns.length > 0) {
      throw new BadRequestError(
        `Tools are not grantable to ${targetUser.type}: ${invalidPatterns
          .slice()
          .sort((a, b) => a.localeCompare(b))
          .join(', ')}`,
      );
    }

    await this.cognitoService.updateUserMcpTools(userId, allowedTools);
    this.logger.info('Updated user MCP tool grant', {
      userId,
      targetUserType: targetUser.type,
      grantedToolCount: allowedTools.length,
      actor: actorEmail,
    });
    return { email: targetUser.email, allowedMcpTools: allowedTools };
  }
}

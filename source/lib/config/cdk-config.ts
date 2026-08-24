// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Tags } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

/**
 * CDK Configuration interface defining all configurable options
 */
export interface CDKConfig {
  solution: {
    id: string;
    name: string;
    trademarkedName: string;
  };
  ttl: {
    findingsDays: number;
    historyDays: number;
    exportFilesDays: number;
    presignedUrlDays: number;
  };
  orchestrator: {
    timeoutHours: number;
    enableAdaptiveConcurrency: boolean;
  };
  sqs: {
    retentionPeriodDays: number;
    dataKeyReuseMinutes: number;
  };
  export: {
    maxTimeMs: number;
    maxRecords: number;
  };
  rateLimiting: {
    stage: {
      rateLimit: number;
      burstLimit: number;
    };
    waf: {
      perUserLimit: number;
      perIpLimit: number;
      sensitiveWriteLimit: number;
      evaluationWindowSec: 60 | 120 | 300 | 600;
      mode: 'count' | 'block';
    };
    alarms: {
      controlStateChangesPerMinute: number;
      sensitiveWritesPerMinute: number;
    };
  };
  memberStackLimits: {
    sc: number;
    nist: number;
    afsbp: number;
  };
  notificationChannels: {
    lambdaMemorySize: number;
    lambdaReservedConcurrency: number;
    lambdaTimeoutSeconds: number;
    webhookLambdaTimeoutSeconds: number;
    logLevel: string;
    secretsResourcePattern: string;
  };
  development: {
    region: string;
    buildEnv: 'development' | 'production';
    customReferenceBucketRegion: string;
  };
  build: {
    distOutputBucket: string;
    distVersion: string;
  };
}

const DEFAULT_CONFIG: CDKConfig = {
  solution: {
    id: 'SO0111',
    name: 'Automated Security Response on AWS',
    trademarkedName: 'automated-security-response-on-aws',
  },
  ttl: {
    findingsDays: 8,
    historyDays: 365,
    exportFilesDays: 30,
    presignedUrlDays: 1,
  },
  orchestrator: {
    timeoutHours: 23,
    enableAdaptiveConcurrency: true,
  },
  sqs: {
    retentionPeriodDays: 14,
    dataKeyReuseMinutes: 60,
  },
  export: {
    maxTimeMs: 26000,
    maxRecords: 50000,
  },
  rateLimiting: {
    // Account-wide stage throttle: a global ceiling far below the 10,000 RPS
    // API Gateway default. Coarse and not per-user — a safety floor only. Set
    // liberally so it never bites legitimate multi-operator usage; it exists to
    // contain a runaway loop, not to enforce per-user limits.
    stage: {
      rateLimit: 500,
      burstLimit: 1000,
    },
    // WAF rate-based rules — the per-user and per-IP rate limiting for the API.
    // WAF's floor is 10 requests per 60s per aggregation instance and it
    // re-evaluates about every 10s, so it bounds abusive bursts rather than
    // enforcing a precise per-second limit. Limits are set above realistic usage
    // (a heavy admin session, or many operators behind a shared egress IP) but
    // low enough to trip on abusive bursts; the sensitive-write rule is tighter
    // as it covers only mutating requests to sensitive paths. Rules run in
    // 'block' mode (over-limit requests get a 429); switch to 'count' to observe
    // via WAF sampled requests without enforcing.
    waf: {
      perUserLimit: 1000,
      perIpLimit: 2000,
      sensitiveWriteLimit: 300,
      evaluationWindowSec: 60,
      mode: 'block',
    },
    alarms: {
      controlStateChangesPerMinute: 5,
      sensitiveWritesPerMinute: 20,
    },
  },
  memberStackLimits: {
    sc: 85,
    nist: 63,
    afsbp: 63,
  },
  notificationChannels: {
    lambdaMemorySize: 256,
    lambdaReservedConcurrency: 10,
    lambdaTimeoutSeconds: 30,
    webhookLambdaTimeoutSeconds: 60,
    logLevel: 'INFO',
    secretsResourcePattern: 'asr/notifications/',
  },
  development: {
    region: 'us-east-1',
    buildEnv: 'production',
    customReferenceBucketRegion: '',
  },
  build: {
    distOutputBucket: '',
    distVersion: '%%VERSION%%',
  },
};

let cachedConfig: CDKConfig | null = null;

/**
 * Deep merge two objects, with source values overriding target values
 */
function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result = { ...target };
  for (const key of Object.keys(source) as (keyof T)[]) {
    const sourceValue = source[key];
    const targetValue = target[key];
    if (
      sourceValue !== undefined &&
      typeof sourceValue === 'object' &&
      sourceValue !== null &&
      !Array.isArray(sourceValue)
    ) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>,
      ) as T[keyof T];
    } else if (sourceValue !== undefined) {
      result[key] = sourceValue as T[keyof T];
    }
  }
  return result;
}

/**
 * Apply environment variable overrides to config.
 * Env vars take precedence over JSON config values.
 */
function applyEnvOverrides(config: CDKConfig): CDKConfig {
  // SOLUTION_ID overrides solution.id
  if (process.env.SOLUTION_ID) {
    config.solution.id = process.env.SOLUTION_ID;
  }

  // SOLUTION_NAME maps to trademarkedName (backward compatibility)
  if (process.env.SOLUTION_NAME) {
    config.solution.trademarkedName = process.env.SOLUTION_NAME;
  }

  // BUILD_ENV overrides development.buildEnv
  if (process.env.BUILD_ENV === 'development' || process.env.BUILD_ENV === 'production') {
    config.development.buildEnv = process.env.BUILD_ENV;
  }

  // AWS_REGION or CDK_DEFAULT_REGION overrides development.region
  if (process.env.AWS_REGION) {
    config.development.region = process.env.AWS_REGION;
  } else if (process.env.CDK_DEFAULT_REGION) {
    config.development.region = process.env.CDK_DEFAULT_REGION;
  }

  // DIST_OUTPUT_BUCKET overrides build.distOutputBucket
  if (process.env.DIST_OUTPUT_BUCKET) {
    config.build.distOutputBucket = process.env.DIST_OUTPUT_BUCKET;
  }

  // DIST_VERSION overrides build.distVersion
  if (process.env.DIST_VERSION) {
    config.build.distVersion = process.env.DIST_VERSION;
  }

  return config;
}

/**
 * Load and return the CDK configuration.
 * Priority: ENV vars > cdk-config.json > DEFAULT_CONFIG
 */
export function getConfig(): CDKConfig {
  if (cachedConfig) return cachedConfig;

  const localConfigPath = path.resolve(__dirname, '../../cdk-config.json');

  if (!fs.existsSync(localConfigPath)) {
    throw new Error(
      'cdk-config.json not found. This file is required for CDK synthesis. ' +
        'Ensure the file exists in source/ directory.',
    );
  }

  let configFile: Partial<CDKConfig>;
  try {
    configFile = JSON.parse(fs.readFileSync(localConfigPath, 'utf8'));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON in cdk-config.json: ${error.message}`);
    }
    throw new Error(`Failed to read cdk-config.json: ${error}`);
  }

  const merged = deepMerge({ ...DEFAULT_CONFIG }, configFile);

  // Apply env var overrides (highest priority)
  const withEnvOverrides = applyEnvOverrides(merged);

  // Validate required fields
  if (!withEnvOverrides.solution.id || !withEnvOverrides.solution.trademarkedName) {
    throw new Error('solution.id and solution.trademarkedName are required (via config or env vars)');
  }

  cachedConfig = withEnvOverrides;
  return cachedConfig;
}

export function getMemberStackLimit(playbook: string): number {
  const config = getConfig();
  const key = playbook.toLowerCase() as keyof typeof config.memberStackLimits;
  return config.memberStackLimits[key] ?? Infinity;
}

/**
 * Apply dynamic tags to a CDK app/construct from the DYNAMIC_TAGS environment variable.
 *
 * Format: "key1=value1,key2=value2" (e.g. "auto-delete=never,auto-stop=no")
 */
export function applyDynamicTags(scope: IConstruct): void {
  const tagsEnv = process.env.DYNAMIC_TAGS;
  if (!tagsEnv) {
    return;
  }

  for (const pair of tagsEnv.split(',')) {
    const [key, ...rest] = pair.split('=');
    if (key && rest.length > 0) {
      Tags.of(scope).add(key.trim(), rest.join('=').trim());
    }
  }
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as fs from 'fs';
import * as path from 'path';

let hashManifest: Record<string, string> | null = null;

/**
 * Loads the Lambda hash manifest generated during build
 */
function loadHashManifest(): Record<string, string> {
  if (hashManifest) {
    return hashManifest;
  }

  // Try to load hash manifest from build output
  const manifestPath = path.join(__dirname, '../../../deployment/regional-s3-assets/lambda/lambda-hashes.json');

  try {
    if (fs.existsSync(manifestPath)) {
      const manifestContent = fs.readFileSync(manifestPath, 'utf-8');
      hashManifest = JSON.parse(manifestContent);
      return hashManifest!;
    }
  } catch (error) {
    console.warn(`Warning: Could not load Lambda hash manifest from ${manifestPath}. Using original filenames.`);
  }

  // Return empty manifest if file doesn't exist (fallback to original names)
  hashManifest = {};
  return hashManifest;
}

/**
 * Creates Lambda code reference from S3 bucket with solution-specific path
 * Automatically uses content-hashed filename if available
 * @param bucket S3 bucket containing Lambda code
 * @param solutionTMN Solution trademarked name (e.g., 'automated-security-response-on-aws')
 * @param solutionVersion Solution version (e.g., 'v3.0.1')
 * @param assetPath Lambda zip file name (e.g., 'asr_lambdas.zip')
 */
export function getLambdaCode(
  bucket: s3.IBucket,
  solutionTMN: string,
  solutionVersion: string,
  assetPath: string,
): lambda.Code {
  const manifest = loadHashManifest();
  const hashedFileName = manifest[assetPath] || assetPath;
  const s3Key = `${solutionTMN}/${solutionVersion}/lambda/${hashedFileName}`;
  return lambda.Code.fromBucket(bucket, s3Key);
}

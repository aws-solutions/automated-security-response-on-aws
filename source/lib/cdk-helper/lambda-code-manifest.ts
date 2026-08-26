// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as fs from 'fs';
import * as path from 'path';

const MANIFEST_PATH = path.join(__dirname, '../../../deployment/regional-s3-assets/lambda/lambda-hashes.json');
let hashManifest: Record<string, string> | null = null;

/**
 * Loads the Lambda hash manifest generated during build
 */
function loadHashManifest(): Record<string, string> {
  if (hashManifest) {
    return hashManifest;
  }

  try {
    if (fs.existsSync(MANIFEST_PATH)) {
      const manifestContent = fs.readFileSync(MANIFEST_PATH, 'utf-8');
      hashManifest = JSON.parse(manifestContent);
      return hashManifest!;
    }
  } catch (error) {
    console.warn(`Warning: Could not load Lambda hash manifest. Using original filenames.`);
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

/**
 * Gets the WebUI manifest hash from the build-generated lambda-hashes.json.
 * This hash triggers UI redeploy when UI source files change.
 */
export function getWebUIManifestHash(): string {
  const manifest = loadHashManifest();
  return manifest['webui-manifest-hash'] || '';
}

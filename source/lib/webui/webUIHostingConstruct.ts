// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CloudFrontToS3 } from '@aws-solutions-constructs/aws-cloudfront-s3';
import { Duration, RemovalPolicy } from 'aws-cdk-lib';
import { HeadersFrameOption, HeadersReferrerPolicy } from 'aws-cdk-lib/aws-cloudfront';
import { Bucket, BucketAccessControl, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export interface UIConstructProps {
  readonly stackName: string;
}

// Creates the infrastructure that will host the web ui (CloudFront, S3 bucket)
export class WebUIHostingConstruct extends Construct {
  bucket: Bucket;
  distributionDomainName: string;

  constructor(scope: Construct, id: string, props: UIConstructProps) {
    super(scope, id);

    const cloudFrontToS3 = new CloudFrontToS3(this, 'Web', {
      insertHttpSecurityHeaders: false,
      responseHeadersPolicyProps: {
        comment: 'Adds a set of recommended security headers',
        customHeadersBehavior: {
          customHeaders: [
            {
              header: 'Cache-Control',
              value: 'no-store, no-cache',
              override: true,
            },
            {
              header: 'Pragma',
              value: 'no-cache',
              override: true,
            },
          ],
        },
        securityHeadersBehavior: {
          contentSecurityPolicy: {
            contentSecurityPolicy:
              "upgrade-insecure-requests; default-src 'none'; manifest-src 'self'; img-src 'self'; font-src data:; connect-src 'self' https:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self';",
            override: true,
          },
          contentTypeOptions: { override: true },
          frameOptions: { frameOption: HeadersFrameOption.DENY, override: true },
          referrerPolicy: { referrerPolicy: HeadersReferrerPolicy.SAME_ORIGIN, override: true },
          strictTransportSecurity: {
            accessControlMaxAge: Duration.days(30),
            includeSubdomains: true,
            override: true,
            preload: true,
          },
        },
      },
      bucketProps: {
        versioned: true,
        encryption: BucketEncryption.S3_MANAGED,
        accessControl: BucketAccessControl.PRIVATE,
        enforceSSL: true,
        removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
        autoDeleteObjects: false,
      },
      cloudFrontLoggingBucketAccessLogBucketProps: {
        removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
      },
      cloudFrontLoggingBucketProps: {
        removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
      },
      cloudFrontDistributionProps: {
        errorResponses: [
          {
            httpStatus: 403,
            ttl: Duration.seconds(300),
            responseHttpStatus: 200,
            responsePagePath: '/index.html',
          },
          {
            httpStatus: 404,
            ttl: Duration.seconds(300),
            responseHttpStatus: 200,
            responsePagePath: '/index.html',
          },
          {
            httpStatus: 400,
            ttl: Duration.seconds(300),
            responseHttpStatus: 200,
            responsePagePath: '/index.html',
          },
        ],
      },
    });

    this.bucket = cloudFrontToS3.s3Bucket as Bucket;
    this.distributionDomainName = cloudFrontToS3.cloudFrontWebDistribution.distributionDomainName;
  }
}

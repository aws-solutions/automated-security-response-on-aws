// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

interface Standard {
  shortname: string;
  longname: string;
}

export interface StandardParamsProps {
  solutionId: string;
}

export class StandardParams extends Construct {
  constructor(scope: Construct, id: string, props: StandardParamsProps) {
    super(scope, id);

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    const standards: Standard[] = [
      {
        shortname: 'AFSBP',
        longname: 'aws-foundational-security-best-practices',
      },
      {
        shortname: 'CIS',
        longname: 'cis-aws-foundations-benchmark',
      },
      {
        shortname: 'PCI',
        longname: 'pci-dss',
      },
      {
        shortname: 'SC',
        longname: 'security-control',
      },
    ];

    for (const standard of standards) {
      new StringParameter(this, `${standard.shortname}ShortName`, {
        description: 'Provides a short (1-12) character abbreviation for the standard.',
        parameterName: `/Solutions/${RESOURCE_PREFIX}/${standard.longname}/shortname`,
        stringValue: standard.shortname,
      });
    }
  }
}

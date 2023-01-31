// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

interface Standard {
  shortname: string;
  longname: string;
  version: string;
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
        version: '1.0.0',
      },
      {
        shortname: 'CIS',
        longname: 'cis-aws-foundations-benchmark',
        version: '1.2.0',
      },
      {
        shortname: 'PCI',
        longname: 'pci-dss',
        version: '3.2.1',
      },
      {
        shortname: 'SC',
        longname: 'security-control',
        version: '2.0.0',
      },
    ];

    const CIS14Standard: Standard = {
      shortname: 'CIS',
      longname: 'cis-aws-foundations-benchmark',
      version: '1.4.0',
    };

    for (const standard of standards) {
      new StringParameter(this, `${standard.shortname}ShortName`, {
        description: 'Provides a short (1-12) character abbreviation for the standard.',
        parameterName: `/Solutions/${RESOURCE_PREFIX}/${standard.longname}/${standard.version}/shortname`,
        stringValue: standard.shortname,
      });
    }

    new StringParameter(this, `${CIS14Standard.shortname}${CIS14Standard.version}ShortName`, {
      description: 'Provides a short (1-12) character abbreviation for the standard.',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/${CIS14Standard.longname}/${CIS14Standard.version}/shortname`,
      stringValue: CIS14Standard.shortname,
    });
  }
}

#!/usr/bin/env node
/*****************************************************************************
 *  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/
import * as cdk from '@aws-cdk/core';
import { CfnRole } from '@aws-cdk/aws-iam';
import { PlaybookConstruct } from '../../../lib/playbook-construct';

export interface CisStackProps {
    description: string;
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionDistName: string;
    solutionName: string;
}

export class CisStack extends cdk.Stack {

  constructor(scope: cdk.Construct, id: string, props: CisStackProps) {
    super(scope, id, props);

    //=========================================================================
    // MAPPINGS
    //=========================================================================
    new cdk.CfnMapping(this, 'SourceCode', {
        mapping: { "General": { 
            "S3Bucket": props.solutionDistBucket,
            "KeyPrefix": props.solutionDistName + '/' + props.solutionVersion
        } }
    })

    //---------------------------------------------------------------------
    // Permissions
    //
    const cisPerms = new cdk.CfnStack(this, "cis-permissions", {
        parameters: {
            "AdminAccountNumber": this.account
        },
        templateUrl: "https://" + cdk.Fn.findInMap("SourceCode", "General", "S3Bucket") +
            "-reference.s3.amazonaws.com/" + cdk.Fn.findInMap("SourceCode", "General", "KeyPrefix") +
            "/playbooks/CISPermissions.template"
    })

    //---------------------------------------------------------------------
    // CIS1314
    //
    let cis1314findings = [
        "1.3 Ensure credentials unused for 90 days or greater are disabled",
        "1.4 Ensure access keys are rotated every 90 days or less"
    ];

    const cis1314playbook = new PlaybookConstruct(this, 'cis1314playbook', {
        name: 'CIS1314',
        description: 'Remediates CIS 1.3 and CIS 1.4 by Deleting IAM Keys over 90 Days Old.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 1.3 & 1.4',
        findings: cis1314findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis1314playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS15111
    //
    let cis15111findings = [
        "1.5 Ensure IAM password policy requires at least one uppercase letter",
        "1.6 Ensure IAM password policy requires at least one lowercase letter",
        "1.7 Ensure IAM password policy requires at least one symbol",
        "1.8 Ensure IAM password policy requires at least one number",
        "1.9 Ensure IAM password policy requires minimum password length of 14 or greater",
        "1.10 Ensure IAM password policy prevents password reuse",
        "1.11 Ensure IAM password policy expires passwords within 90 days or less"
    ];

    const cis15111playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis15111playbook', {
        name: 'CIS15111',
        description: 'Remediates CIS 1.5 to 1.11 by establishing a CIS compliant strong password policy.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 1.5 - 1.11',
        findings: cis15111findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis15111playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS116
    //
    let cis116findings = [
      "1.16 Ensure IAM policies are attached only to groups or roles",
    ];

    const cis116playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis116playbook', {
      name: 'CIS116',
      description: 'Remediates CIS 1.16 by adding users to a new group with polices obtained from the users.',
      aws_region: this.region,
      aws_partition: this.partition,
      aws_accountid: this.account,
      custom_action_name: 'CIS 1.16',
      findings: cis116findings,
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionName: props.solutionName,
      distName: props.solutionDistName,
      distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis116playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS120
    //
    let cis120findings = [
      "1.20 Ensure a support role has been created to manage incidents with AWS Support",
    ];

    const cis120playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis120playbook', {
      name: 'CIS120',
      description: 'Remediates CIS 1.20 by creating the role to manage incidents with AWS Support',
      aws_region: this.region,
      aws_partition: this.partition,
      aws_accountid: this.account,
      custom_action_name: 'CIS 1.20',
      findings: cis120findings,
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionName: props.solutionName,
      distName: props.solutionDistName,
      distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis120playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS22
    //
    let cis22findings = [
        "2.2 Ensure CloudTrail log file validation is enabled"
    ];

    const cis22playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis22playbook', {
        name: 'CIS22',
        description: 'Remediates CIS 2.2 by enabling CloudTrail log file validation.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.2',
        findings: cis22findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis22playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS23
    //
    let cis23findings = [
        "2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"
    ];

    const cis23playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis23playbook', {
        name: 'CIS23',
        description: 'Remediates CIS 2.3 by making CloudTrail log bucket private.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.3',
        findings: cis23findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis23playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS24
    //
    let cis24findings = [
        "2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs"
    ];

    const cis24playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis24playbook', {
        name: 'CIS24',
        description: 'Remediates CIS 2.4 by enabling CloudWatch logging for CloudTrail.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.4',
        findings: cis24findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis24playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS26
    //
    let cis26findings = [
        "2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
    ]

    const cis26playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis26playbook', {
        name: 'CIS26',
        description: 'Remediates CIS 2.6 enabling Access Logging on CloudTrail logs bucket.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.6',
        findings: cis26findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis26playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS27
    //
    let cis27findings = [
        "2.7 Ensure CloudTrail logs are encrypted at rest using AWS KMS CMKs"
    ]

    const cis27playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis27playbook', {
        name: 'CIS27',
        description: 'Remediates CIS 2.7 encrypt Cloudtrail logs at rest using AWS KMS CMKs.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.7',
        findings: cis27findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis27playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS28
    //
    let cis28findings = [
        "2.8 Ensure rotation for customer created CMKs is enabled"
    ];

    const cis28playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis28playbook', {
        name: 'CIS28',
        description: 'Remediates CIS 2.8 by enabling customer CMK key rotation.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.8',
        findings: cis28findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis28playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS29
    //
    let cis29findings = [
        "2.9 Ensure VPC flow logging is enabled in all VPCs"
    ];

    const cis29playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis29playbook', {
        name: 'CIS29',
        description: 'Remediates CIS 2.9 enabling VPC flow logging in all VPCs.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 2.9',
        findings: cis29findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis29playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS4142
    //
    let cis4142findings = [
        "4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
    ];

    const cis4142playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis4142playbook', {
        name: 'CIS4142',
        description: 'Remediates CIS 4.1 and 4.2 by disallowing global ingress on port 22 and 3389.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 4.1 & 4.2',
        findings: cis4142findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis4142playbook.lambdaRole.node.findChild('Resource') as CfnRole)

    //---------------------------------------------------------------------
    // CIS43
    //
    let cis43findings = [
        "4.3 Ensure the default security group of every VPC restricts all traffic"
    ];

    const cis43playbook: PlaybookConstruct = new PlaybookConstruct(this, 'cis43playbook', {
        name: 'CIS43',
        description: 'Remediates CIS 4.3 by removing all rules from a default security group.',
        aws_region: this.region,
        aws_partition: this.partition,
        aws_accountid: this.account,
        custom_action_name: 'CIS 4.3',
        findings: cis43findings,
        solutionId: props.solutionId,
        solutionVersion: props.solutionVersion,
        solutionName: props.solutionName,
        distName: props.solutionDistName,
        distBucket: props.solutionDistBucket
    });
    cisPerms.addDependsOn(cis43playbook.lambdaRole.node.findChild('Resource') as CfnRole)
  }
}

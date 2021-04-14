import {Effect, PolicyDocument, PolicyStatement} from '@aws-cdk/aws-iam';
import {PlaybookConstruct} from '../lib/playbook-construct';
import {AssumeRoleConstruct} from '../lib/assume-role-construct';
import * as cdk from '@aws-cdk/core';


export class TestPlaybook extends cdk.Stack {
    constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
        super(scope, id);

        let findings = {
            "Title": [
                "2.9 Ensure VPC flow logging is enabled in all VPCs."
            ]
        };

        const construct = new PlaybookConstruct(this, 'test', {
            name: 'CIS_1.X_RR',
            description: 'Test remediation',
            aws_region: this.region,
            aws_partition: this.partition,
            aws_accountid: this.account,
            custom_action_name: 'CIS 1.X Remediation.',
            findings: findings,
            solutionId: 'SO0111',
            solutionName: 'AWS Security Hub Automatic Response and Remediation',
            solutionVersion: 'v1.0.0',
            distName: 'aws-security-hub-automatic-response-and-remediation',
            distBucket: 'sharr'
        });
    }
}

export class TestAssumeRole extends cdk.Stack {
    constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
        super(scope, id);

        const adminAccountNumber = new cdk.CfnParameter(this, 'Admin Account Number', {
            description: "Admin account number ",
            type: "Number"
        });

        //CIS 2.4
        const cis24 = new PolicyStatement();
        cis24.addActions("cloudtrail:UpdateTrail")
        cis24.effect = Effect.ALLOW
        cis24.addResources("arn:" + this.partition + ":cloudtrail::" + this.account + ":*");

        const cis24Policy = new PolicyDocument();
        cis24Policy.addStatements(cis24)

        const cis24AssumeRole = new AssumeRoleConstruct(this, 'cis24assumerole', {
            adminAccountNumber: adminAccountNumber,
            solutionId: 'SO0111',
            lambdaPolicy: cis24Policy,
            lambdaHandlerName: 'CIS24',
            region: this.region,
            aws_partition: this.partition
        });
    }
}


import {expect as expectCDK, haveResourceLike, ResourcePart, SynthUtils} from '@aws-cdk/assert';
import { App, Stack } from '@aws-cdk/core';
import { 
  Policy, 
  PolicyStatement,
  Effect
} from '@aws-cdk/aws-iam';
import { SsmPlaybook, Trigger, SsmRole, SsmRemediationRunbook } from '../lib/ssmplaybook';

// ----------------------------
// SsmPlaybook - Parse Runbook
// ----------------------------
function getSsmPlaybook(): Stack {
    const app = new App();
    const stack = new Stack(app, 'MyTestStack', {
      stackName: 'testStack'
    });
    new SsmPlaybook(stack, 'Playbook', {
      securityStandard: 'SECTEST',
      securityStandardVersion: '1.2.3',
      controlId: 'TEST.1',
      ssmDocPath: 'test/test_data/',
      ssmDocFileName: 'tstest-rds1.yaml',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'solutionstest'
    })
    return stack;
}
test('Test SsmPlaybook Generation', () => {
  expectCDK(getSsmPlaybook()).to(haveResourceLike("AWS::SSM::Document", {
    "Content": {
      "description": "### Document Name - SHARR-SECTEST_1.2.3_TEST.1\n",
      "schemaVersion": "0.3",
      "assumeRole": "{{ AutomationAssumeRole }}",
      "outputs": [
        "VerifySGRules.Response"
      ],
      "parameters": {
        "Finding": {
          "type": "StringMap",
          "description": "The input from Step function for TEST1 finding"
        },
        "AutomationAssumeRole": {
          "type": "String",
          "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
          "default": ""
        }
      }
    },
    "DocumentType": "Automation",
    "Name": "SHARR-SECTEST_1.2.3_TEST.1"
  }, ResourcePart.Properties));
});

// -------------------
// Trigger
// -------------------
function getTriggerStack(): Stack {
    const app = new App();
    const stack = new Stack(app, 'MyTestStack', {
      stackName: 'testStack'
    });
    new Trigger(stack, 'Trigger', {
      description: 'Trigger description',
      securityStandard: 'AFSBP',
      generatorId: 'aws-foundational-security-best-practices/v/1.0.0/RDS.1',
      controlId: 'RDS.1',
      targetArn: 'arn:aws-test:sns:us-east-1:1111111111111111:foo'
    })
    return stack;
}

// ---------------------
// SsmRemediationRunbook
// ---------------------
function getSsmRemediationRunbook(): Stack {
    const app = new App();
    const stack = new Stack(app, 'MyTestStack', {
      stackName: 'testStack'
    });
    new SsmRemediationRunbook(stack, 'Playbook', {
      ssmDocName: 'blahblahblah',
      ssmDocPath: 'test/test_data/',
      ssmDocFileName: 'tstest-cis29.yaml',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'solutionstest'
    })
    return stack;
}
test('Test Shared Remediation Generation', () => {
  expectCDK(getSsmRemediationRunbook()).to(haveResourceLike("AWS::SSM::Document", {
    "Content": {
      "description": "### Document Name - SHARR-CIS_1.2.0_2.9\n",
      "schemaVersion": "0.3",
      "assumeRole": "{{ AutomationAssumeRole }}",
      "outputs": [
        "VerifySGRules.Response"
      ],
      "parameters": {
        "Finding": {
          "type": "StringMap",
          "description": "The input from Step function for 2.9 finding"
        },
        "AutomationAssumeRole": {
          "type": "String",
          "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
          "default": ""
        }
      }
    },
    "DocumentType": "Automation",
    "Name": "SHARR-blahblahblah"
  }, ResourcePart.Properties));
});

// ------------------
// SsmRole
// ------------------
function getSsmRemediationRoleCis(): Stack {
    const app = new App();
    const stack = new Stack(app, 'MyTestStack', {
      stackName: 'testStack'
    });
    let inlinePolicy = new Policy(stack, 'Policy')
    let rdsPerms = new PolicyStatement();
    rdsPerms.addActions("rds:ModifyDBSnapshotAttribute")
    rdsPerms.effect = Effect.ALLOW
    rdsPerms.addResources("*");
    inlinePolicy.addStatements(rdsPerms)

    new SsmRole(stack, 'Role', {
      solutionId: "SO0111",
      ssmDocName: "foobar",
      adminAccountNumber: "111111111111",
      remediationPolicy: inlinePolicy,
      remediationRoleName: "SHARR-RemediationRoleName"
    })
    return stack;
}

test('Test SsmRole Generation', () => {
  expectCDK(getSsmRemediationRoleCis()).to(haveResourceLike("AWS::IAM::Role", {
    "AssumeRolePolicyDocument": {
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Effect": "Allow",
          "Principal": {
            "AWS": {
              "Fn::Join": [
                "",
                [
                  "arn:",
                  {
                    "Ref": "AWS::Partition"
                  },
                  ":iam::111111111111:role/SO0111-SHARR-Orchestrator-Admin_",
                  {
                    "Ref": "AWS::Region"
                  }
                ]
              ]
            },
            "Service": "ssm.amazonaws.com"
          }
        }
      ],
      "Version": "2012-10-17"
    },
    "RoleName": "SHARR-RemediationRoleName"
  }, ResourcePart.Properties));
});

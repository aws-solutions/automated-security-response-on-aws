import {expect as expectCDK, haveResourceLike, ResourcePart, SynthUtils} from '@aws-cdk/assert';
// import * as cdk from '@aws-cdk/core';
import { App, Stack } from '@aws-cdk/core';
import { 
  Policy, 
  PolicyStatement,
  Effect
} from '@aws-cdk/aws-iam';
import * as TestStack from './test-stack';
import {
  PlaybookConstruct,
  SsmPlaybook,
  SsmRemediationRole,
  Trigger
} from '../lib/playbook-construct';

function getTestStack(): Stack {
    const envEU  = { account: '111111111111', region: 'eu-west-1' };
    const app = new App();
    const stack = new TestStack.TestPlaybook(app, 'MyTestStack', {env: envEU});
    return stack;
}

test('Test the playbook to have all the required resources.', () => {

    process.env.DIST_OUTPUT_BUCKET = 'solutions'
    process.env.DIST_SOLUTION_NAME = 'aws-security-hub-automated-response-and-remediation'
    process.env.DIST_VERSION = 'v1.0.0'

    expectCDK(getTestStack()).to(haveResourceLike("AWS::Lambda::Function", {}, ResourcePart.Properties))
    expectCDK(getTestStack()).to(haveResourceLike("AWS::IAM::Role", {
        "AssumeRolePolicyDocument": {
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": "lambda.amazonaws.com"
              }
            }
          ],
          "Version": "2012-10-17"
        },
        "Policies": [
          {
            "PolicyDocument": {
              "Statement": [
                {
                  "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                  ],
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action": [
                    "cloudwatch:PutMetricData",
                    "securityhub:BatchUpdateFindings"
                  ],
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action": "sns:Publish",
                  "Effect": "Allow",
                  "Resource": {
                    "Fn::Join": [
                      "",
                      [
                        "arn:",
                        {
                          "Ref": "AWS::Partition"
                        },
                        ":sns:",
                        {
                          "Ref": "AWS::Region"
                        },
                        ":",
                        {
                          "Ref": "AWS::AccountId"
                        },
                        ":SO0111-SHARR_Topic"
                      ]
                    ]
                  }
                },
                {
                  "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:GenerateDataKey"
                  ],
                  "Effect": "Allow",
                  "Resource": "{{resolve:ssm:/Solutions/SO0111/CMK_ARN:1}}"
                },
                {
                  "Action": "sts:AssumeRole",
                  "Effect": "Allow",
                  "Resource": {
                    "Fn::Join": [
                      "",
                      [
                        "arn:",
                        {
                          "Ref": "AWS::Partition"
                        },
                        ":iam::*:role/SO0111_CIS_1.X_RR_memberRole_",
                        {
                          "Ref": "AWS::Region"
                        }
                      ]
                    ]
                  }
                }
              ],
              "Version": "2012-10-17"
            },
            "PolicyName": "default_lambdaPolicy"
          }
        ],
        "RoleName": {
              "Fn::Join": [
                "",
                [
                  "SO0111_CIS_1.X_RR_lambdaRole_",
                  {
                    "Ref": "AWS::Region"
                  }
                ]
              ]
            }
    }, ResourcePart.Properties))
    expectCDK(getTestStack()).to(haveResourceLike("AWS::Lambda::Permission", {}, ResourcePart.Properties))
});

test('check custom action target', () => {

    process.env.DIST_OUTPUT_BUCKET = 'solutions'
    process.env.DIST_SOLUTION_NAME = 'aws-security-hub-automated-response-and-remediation'
    process.env.DIST_VERSION = 'v1.0.0'

    expectCDK(getTestStack()).to(haveResourceLike("Custom::ActionTarget", {
        "Name": "CIS 1.X Remediation.",
        "Description": "Test remediation",
        "Id": "CIS_1.X_RR",
        "ServiceToken": {
            "Fn::Join": [
                "",
                [
                    "arn:",
                    {
                      "Ref": "AWS::Partition"
                    },
                    ":lambda:",
                    {
                        "Ref": "AWS::Region"
                    },
                    ":",
                    {
                        "Ref": "AWS::AccountId"
                    },
                    ":function:SO0111-SHARR-CustomAction"
                ]
            ]
        },
    }, ResourcePart.Properties));
});

test('check if the events rule is created', () => {

    process.env.DIST_OUTPUT_BUCKET = 'solutions'
    process.env.DIST_SOLUTION_NAME = 'aws-security-hub-automated-response-and-remediation'
    process.env.DIST_VERSION = 'v1.0.0'

    expectCDK(getTestStack()).to(haveResourceLike('AWS::Events::Rule', {
        "Description": "Test remediation event rule.",
        "EventPattern": {
            "source": [
                "aws.securityhub"
            ],
            "detail-type": [
                "Security Hub Findings - Custom Action"
            ]
        },
        "Name": "CIS_1.X_RR_eventRule",
        "State": "ENABLED"
    }, ResourcePart.Properties));
});

// -----------
// SsmPlaybook
// -----------
function getSsmPlaybook(): Stack {
    const app = new App();
    const stack = new Stack(app, 'MyTestStack', {
      stackName: 'testStack'
    });
    new SsmPlaybook(stack, 'Playbook', {
      securityStandard: 'AFSBP',
      controlId: 'RDS.1',
      ssmDocPath: 'test/test_data/',
      ssmDocFileName: 'tstest.yaml'
    })
    return stack;
}
test('Test SsmPlaybook Generation', () => {
  expectCDK(getSsmPlaybook()).to(haveResourceLike("AWS::SSM::Document", {
    "Content": {
      "description": "### Document Name - SHARR_Remediation_AFSBP_EC2.2\n",
      "schemaVersion": "0.3",
      "assumeRole": "{{ AutomationAssumeRole }}",
      "outputs": [
        "VerifySGRules.Response"
      ],
      "parameters": {
        "Finding": {
          "type": "StringMap",
          "description": "The input from Step function for EC22 finding"
        },
        "AutomationAssumeRole": {
          "type": "String",
          "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
          "default": ""
        }
      }
    },
    "DocumentType": "Automation",
    "Name": "SHARR_Remediation_AFSBP_RDS.1"
  }, ResourcePart.Properties));
});

// ------------------
// SsmRemediationRole
// ------------------
function getSsmRemediationRole(): Stack {
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

    new SsmRemediationRole(stack, 'Role', {
      "solutionId": "SO01111",
      "controlId": "ABC.1",
      "adminAccountNumber": "111111111111",
      "remediationPolicy": inlinePolicy,
      "adminRoleName": 'SHARR-AdminRoleName',
      "remediationRoleName": "SHARR-RemediationRoleName"
    })
    return stack;
}

test('Test SsmRemediationRole Generation', () => {
  expectCDK(getSsmRemediationRole()).to(haveResourceLike("AWS::IAM::Role", {
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
                  ":iam::111111111111:role/SHARR-AdminRoleName"
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

function getTriggerStack(): Stack {
    const app = new App();
    const stack = new Stack(app, 'MyTestStack', {
      stackName: 'testStack'
    });
    new Trigger(stack, 'Trigger', {
      description: 'Trigger description',
      securityStandard: 'AFSBP',
      securityStandardArn: 'arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0',
      controlId: 'RDS.1',
      targetArn: 'arn:aws-test:sns:us-east-1:1111111111111111:foo'
    })
    return stack;
}

// -------
// Trigger
// -------
test('Test Trigger Generation', () => {
  expectCDK(getTriggerStack()).to(haveResourceLike("Custom::ActionTarget", {
      "ServiceToken": {
        "Fn::Join": [
          "",
          [
            "arn:",
            {
              "Ref": "AWS::Partition"
            },
            ":lambda:",
            {
              "Ref": "AWS::Region"
            },
            ":",
            {
              "Ref": "AWS::AccountId"
            },
            ":function:SO0111-SHARR-CustomAction"
          ]
        ]
      },
      "Name": "AFSBP RDS.1",
      "Description": "Trigger description",
      "Id": "AFSBPRDS1"
  }, ResourcePart.Properties));
});

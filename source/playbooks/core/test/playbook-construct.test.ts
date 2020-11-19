import {expect as expectCDK, haveResourceLike, ResourcePart, SynthUtils} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as TestStack from './test-stack';

function getTestStack(): cdk.Stack {
    const envEU  = { account: '111111111111', region: 'eu-west-1' };
    const app = new cdk.App();
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

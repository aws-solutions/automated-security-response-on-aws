###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.         #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################


CIS_mappings = {
    "3.1": {
        "filter_name": "UnauthorizedAPICalls",
        "filter_pattern": '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}',
        "metric_name": "UnauthorizedAPICalls",
        "metric_value": 1,
        "alarm_name": "UnauthorizedAPICalls",
        "alarm_desc": "Alarm for UnauthorizedAPICalls > 0",
        "alarm_threshold": 1
    },
    "3.2": {
        "filter_name": "ConsoleSigninWithoutMFA",
        "filter_pattern": '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}',
        "metric_name": "ConsoleSigninWithoutMFA",
        "metric_value": 1,
        "alarm_name": "ConsoleSigninWithoutMFA",
        "alarm_desc": "Alarm for ConsoleSigninWithoutMFA > 0",
        "alarm_threshold": 1
    },
    "3.3": {
        "filter_name": "RootAccountUsage",
        "filter_pattern": '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
        "metric_name": "RootAccountUsage",
        "metric_value": 1,
        "alarm_name": "RootAccountUsage",
        "alarm_desc": "Alarm for RootAccountUsage > 0",
        "alarm_threshold": 1
    },
    "3.4": {
        "filter_name": "IAMPolicyChanges",
        "filter_pattern": '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}',
        "metric_name": "IAMPolicyChanges",
        "metric_value": 1,
        "alarm_name": "IAMPolicyChanges",
        "alarm_desc": "Alarm for IAMPolicyChanges > 0",
        "alarm_threshold": 1
    },
    "3.5": {
        "filter_name": "CloudTrailChanges",
        "filter_pattern": '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}',
        "metric_name": "CloudTrailChanges",
        "metric_value": 1,
        "alarm_name": "CloudTrailChanges",
        "alarm_desc": "Alarm for CloudTrailChanges > 0",
        "alarm_threshold": 1
    },
    "3.6": {
        "filter_name": "ConsoleAuthenticationFailure",
        "filter_pattern": '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}',
        "metric_name": "ConsoleAuthenticationFailure",
        "metric_value": 1,
        "alarm_name": "ConsoleAuthenticationFailure",
        "alarm_desc": "Alarm for ConsoleAuthenticationFailure > 0",
        "alarm_threshold": 1
    },
    "3.7": {
        "filter_name": "DisableOrDeleteCMK",
        "filter_pattern": '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}',
        "metric_name": "DisableOrDeleteCMK",
        "metric_value": 1,
        "alarm_name": "DisableOrDeleteCMK",
        "alarm_desc": "Alarm for DisableOrDeleteCMK > 0",
        "alarm_threshold": 1
    },
    "3.8": {
        "filter_name": "S3BucketPolicyChanges",
        "filter_pattern": '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}',
        "metric_name": "S3BucketPolicyChanges",
        "metric_value": 1,
        "alarm_name": "S3BucketPolicyChanges",
        "alarm_desc": "Alarm for S3BucketPolicyChanges > 0",
        "alarm_threshold": 1
    },
    "3.9": {
        "filter_name": "AWSConfigChanges",
        "filter_pattern": '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}',
        "metric_name": "AWSConfigChanges",
        "metric_value": 1,
        "alarm_name": "AWSConfigChanges",
        "alarm_desc": "Alarm for AWSConfigChanges > 0",
        "alarm_threshold": 1
    },
    "3.10": {
        "filter_name": "SecurityGroupChanges",
        "filter_pattern": '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}',
        "metric_name": "SecurityGroupChanges",
        "metric_value": 1,
        "alarm_name": "SecurityGroupChanges",
        "alarm_desc": "Alarm for SecurityGroupChanges > 0",
        "alarm_threshold": 1
    },
    "3.11": {
        "filter_name": "NetworkACLChanges",
        "filter_pattern": '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}',
        "metric_name": "NetworkACLChanges",
        "metric_value": 1,
        "alarm_name": "NetworkACLChanges",
        "alarm_desc": "Alarm for NetworkACLChanges > 0",
        "alarm_threshold": 1
    },
    "3.12": {
        "filter_name": "NetworkGatewayChanges",
        "filter_pattern": '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}',
        "metric_name": "NetworkGatewayChanges",
        "metric_value": 1,
        "alarm_name": "NetworkGatewayChanges",
        "alarm_desc": "Alarm for NetworkGatewayChanges > 0",
        "alarm_threshold": 1
    },
    "3.13": {
        "filter_name": "RouteTableChanges",
        "filter_pattern": '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}',
        "metric_name": "RouteTableChanges",
        "metric_value": 1,
        "alarm_name": "RouteTableChanges",
        "alarm_desc": "Alarm for RouteTableChanges > 0",
        "alarm_threshold": 1
    },
    "3.14": {
        "filter_name": "VPCChanges",
        "filter_pattern": '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}',
        "metric_name": "VPCChanges",
        "metric_value": 1,
        "alarm_name": "VPCChanges",
        "alarm_desc": "Alarm for VPCChanges > 0",
        "alarm_threshold": 1
    }
}


def verify(event, context):
    
    return CIS_mappings.get(event['ControlId'], None)
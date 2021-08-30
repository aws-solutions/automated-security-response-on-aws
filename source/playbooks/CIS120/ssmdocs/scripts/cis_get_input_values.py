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
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_1",
        "filter_pattern": '{$.errorCode = "AccessDenied" || $.errorCode = "UnauthorizedOperation"}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_1_UnauthorizedAPICalls",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_1_UnauthorizedAPICalls",
        "alarm_desc": "Alarm for CIS finding 3.1-UnauthorizedAPICalls",
        "alarm_threshold": 1
    },
    "3.2": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_2_ConsoleSigninWithoutMFA",
        "filter_pattern": '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_2_ConsoleSigninWithoutMFA",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_2_ConsoleSigninWithoutMFA",
        "alarm_desc": "Alarm for CIS finding 3.2 ConsoleSigninWithoutMFA",
        "alarm_threshold": 1
    },
    "3.3": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_3_RootAccountUsage",
        "filter_pattern": '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_3_RootAccountUsage",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_3_RootAccountUsage",
        "alarm_desc": "Alarm for CIS finding 3.3 RootAccountUsage",
        "alarm_threshold": 1

    },
    "3.4": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_4_IAMPolicyChanges",
        "filter_pattern": '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_4_IAMPolicyChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_4_IAMPolicyChanges",
        "alarm_desc": "Alarm for CIS finding 3.4 IAMPolicyChanges",
        "alarm_threshold": 1
    },
    "3.5": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_5_CloudTrailChanges",
        "filter_pattern": '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_5_CloudTrailChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_5_CloudTrailChanges",
        "alarm_desc": "Alarm for CIS finding 3.5 CloudTrailChanges",
        "alarm_threshold": 1
    },
    "3.6": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_6_ConsoleAuthenticationFailure",
        "filter_pattern": '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_6_ConsoleAuthenticationFailure",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_6_ConsoleAuthenticationFailure",
        "alarm_desc": "Alarm for CIS finding 3.6 ConsoleAuthenticationFailure",
        "alarm_threshold": 1
    },
    "3.7": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_7_DisableOrDeleteCMK",
        "filter_pattern": '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_7_DisableOrDeleteCMK",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_7_DisableOrDeleteCMK",
        "alarm_desc": "Alarm for CIS finding 3.7 DisableOrDeleteCMK",
        "alarm_threshold": 1
    },
    "3.8": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_8_S3BucketPolicyChanges",
        "filter_pattern": '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_8_S3BucketPolicyChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_8_S3BucketPolicyChanges",
        "alarm_desc": "Alarm for CIS finding 3.8 S3BucketPolicyChanges",
        "alarm_threshold": 1
    },
    "3.9": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_9_AWSConfigChanges",
        "filter_pattern": '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_9_AWSConfigChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_9_AWSConfigChanges",
        "alarm_desc": "Alarm for CIS finding 3.9 AWSConfigChanges",
        "alarm_threshold": 1
    },
    "3.10": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_10_SecurityGroupChanges",
        "filter_pattern": '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_10_SecurityGroupChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_10_SecurityGroupChanges",
        "alarm_desc": "Alarm for CIS finding 3.10 SecurityGroupChanges",
        "alarm_threshold": 1
    },
    "3.11": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_11_NetworkACLChanges",
        "filter_pattern": '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_11_NetworkACLChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_11_NetworkACLChanges",
        "alarm_desc": "Alarm for CIS finding 3.11 NetworkACLChanges",
        "alarm_threshold": 1
    },
    "3.12": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_12_NetworkGatewayChanges",
        "filter_pattern": '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_12_NetworkGatewayChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_12_NetworkGatewayChanges",
        "alarm_desc": "Alarm for CIS finding 3.12 NetworkGatewayChanges",
        "alarm_threshold": 1
    },
    "3.13": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_13_RouteTableChanges",
        "filter_pattern": '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_13_RouteTableChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_13_RouteTableChanges",
        "alarm_desc": "Alarm for CIS finding 3.13 RouteTableChanges",
        "alarm_threshold": 1
    },
    "3.14": {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_14_VPCChanges",
        "filter_pattern": '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_14_VPCChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_14_VPCChanges",
        "alarm_desc": "Alarm for CIS finding 3.14 VPCChanges",
        "alarm_threshold": 1
    }
}


def verify(event, context):
    
    return CIS_mappings.get(event['ControlId'], None)

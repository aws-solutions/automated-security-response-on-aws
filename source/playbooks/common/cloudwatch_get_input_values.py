# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

unauthorizedAPICallsFilter = {
    "filter_name": "UnauthorizedAPICalls",
    "filter_pattern": '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}',
    "metric_name": "UnauthorizedAPICalls",
    "metric_value": 1,
    "alarm_name": "UnauthorizedAPICalls",
    "alarm_desc": "Alarm for UnauthorizedAPICalls > 0",
    "alarm_threshold": 1,
}

consoleSignInWithoutMFAFilter = {
    "filter_name": "ConsoleSigninWithoutMFA",
    "filter_pattern": '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}',
    "metric_name": "ConsoleSigninWithoutMFA",
    "metric_value": 1,
    "alarm_name": "ConsoleSigninWithoutMFA",
    "alarm_desc": "Alarm for ConsoleSigninWithoutMFA > 0",
    "alarm_threshold": 1,
}

rootAccountUsageFilter = {
    "filter_name": "RootAccountUsage",
    "filter_pattern": '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
    "metric_name": "RootAccountUsage",
    "metric_value": 1,
    "alarm_name": "RootAccountUsage",
    "alarm_desc": "Alarm for RootAccountUsage > 0",
    "alarm_threshold": 1,
}

iamPolicyChangesFilter = {
    "filter_name": "IAMPolicyChanges",
    "filter_pattern": "{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}",
    "metric_name": "IAMPolicyChanges",
    "metric_value": 1,
    "alarm_name": "IAMPolicyChanges",
    "alarm_desc": "Alarm for IAMPolicyChanges > 0",
    "alarm_threshold": 1,
}

cloudtrailChangesFilter = {
    "filter_name": "CloudTrailChanges",
    "filter_pattern": "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}",
    "metric_name": "CloudTrailChanges",
    "metric_value": 1,
    "alarm_name": "CloudTrailChanges",
    "alarm_desc": "Alarm for CloudTrailChanges > 0",
    "alarm_threshold": 1,
}

consoleAuthenticationFailureFilter = {
    "filter_name": "ConsoleAuthenticationFailure",
    "filter_pattern": '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}',
    "metric_name": "ConsoleAuthenticationFailure",
    "metric_value": 1,
    "alarm_name": "ConsoleAuthenticationFailure",
    "alarm_desc": "Alarm for ConsoleAuthenticationFailure > 0",
    "alarm_threshold": 1,
}

disableOrDeleteCMKFilter = {
    "filter_name": "DisableOrDeleteCMK",
    "filter_pattern": "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}",
    "metric_name": "DisableOrDeleteCMK",
    "metric_value": 1,
    "alarm_name": "DisableOrDeleteCMK",
    "alarm_desc": "Alarm for DisableOrDeleteCMK > 0",
    "alarm_threshold": 1,
}

s3BucketPolicyChangesFilter = {
    "filter_name": "S3BucketPolicyChanges",
    "filter_pattern": "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}",
    "metric_name": "S3BucketPolicyChanges",
    "metric_value": 1,
    "alarm_name": "S3BucketPolicyChanges",
    "alarm_desc": "Alarm for S3BucketPolicyChanges > 0",
    "alarm_threshold": 1,
}

awsConfigChangesFilter = {
    "filter_name": "AWSConfigChanges",
    "filter_pattern": "{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}",
    "metric_name": "AWSConfigChanges",
    "metric_value": 1,
    "alarm_name": "AWSConfigChanges",
    "alarm_desc": "Alarm for AWSConfigChanges > 0",
    "alarm_threshold": 1,
}

securityGroupChangesFilter = {
    "filter_name": "SecurityGroupChanges",
    "filter_pattern": "{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}",
    "metric_name": "SecurityGroupChanges",
    "metric_value": 1,
    "alarm_name": "SecurityGroupChanges",
    "alarm_desc": "Alarm for SecurityGroupChanges > 0",
    "alarm_threshold": 1,
}

networkACLChangesFilter = {
    "filter_name": "NetworkACLChanges",
    "filter_pattern": "{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}",
    "metric_name": "NetworkACLChanges",
    "metric_value": 1,
    "alarm_name": "NetworkACLChanges",
    "alarm_desc": "Alarm for NetworkACLChanges > 0",
    "alarm_threshold": 1,
}

networkGatewayChangesFilter = {
    "filter_name": "NetworkGatewayChanges",
    "filter_pattern": "{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}",
    "metric_name": "NetworkGatewayChanges",
    "metric_value": 1,
    "alarm_name": "NetworkGatewayChanges",
    "alarm_desc": "Alarm for NetworkGatewayChanges > 0",
    "alarm_threshold": 1,
}

routeTableChangesFilter = {
    "filter_name": "RouteTableChanges",
    "filter_pattern": "{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}",
    "metric_name": "RouteTableChanges",
    "metric_value": 1,
    "alarm_name": "RouteTableChanges",
    "alarm_desc": "Alarm for RouteTableChanges > 0",
    "alarm_threshold": 1,
}

vpcChangesFilter = {
    "filter_name": "VPCChanges",
    "filter_pattern": "{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}",
    "metric_name": "VPCChanges",
    "metric_value": 1,
    "alarm_name": "VPCChanges",
    "alarm_desc": "Alarm for VPCChanges > 0",
    "alarm_threshold": 1,
}

Cloudwatch_mappings = {
    "cis-aws-foundations-benchmark": {
        "1.2.0": {
            "3.1": unauthorizedAPICallsFilter,
            "3.2": consoleSignInWithoutMFAFilter,
            "3.3": rootAccountUsageFilter,
            "3.4": iamPolicyChangesFilter,
            "3.5": cloudtrailChangesFilter,
            "3.6": consoleAuthenticationFailureFilter,
            "3.7": disableOrDeleteCMKFilter,
            "3.8": s3BucketPolicyChangesFilter,
            "3.9": awsConfigChangesFilter,
            "3.10": securityGroupChangesFilter,
            "3.11": networkACLChangesFilter,
            "3.12": networkGatewayChangesFilter,
            "3.13": routeTableChangesFilter,
            "3.14": vpcChangesFilter,
        },
        "1.4.0": {
            "4.3": rootAccountUsageFilter,
            "4.4": iamPolicyChangesFilter,
            "4.5": cloudtrailChangesFilter,
            "4.6": consoleAuthenticationFailureFilter,
            "4.7": disableOrDeleteCMKFilter,
            "4.8": s3BucketPolicyChangesFilter,
            "4.9": awsConfigChangesFilter,
            "4.10": securityGroupChangesFilter,
            "4.11": networkACLChangesFilter,
            "4.12": networkGatewayChangesFilter,
            "4.13": routeTableChangesFilter,
            "4.14": vpcChangesFilter,
        },
    },
    "security-control": {
        "2.0.0": {
            "CloudWatch.1": rootAccountUsageFilter,
            "CloudWatch.2": unauthorizedAPICallsFilter,
            "CloudWatch.3": consoleSignInWithoutMFAFilter,
            "CloudWatch.4": iamPolicyChangesFilter,
            "CloudWatch.5": cloudtrailChangesFilter,
            "CloudWatch.6": consoleAuthenticationFailureFilter,
            "CloudWatch.7": disableOrDeleteCMKFilter,
            "CloudWatch.8": s3BucketPolicyChangesFilter,
            "CloudWatch.9": awsConfigChangesFilter,
            "CloudWatch.10": securityGroupChangesFilter,
            "CloudWatch.11": networkACLChangesFilter,
            "CloudWatch.12": networkGatewayChangesFilter,
            "CloudWatch.13": routeTableChangesFilter,
            "CloudWatch.14": vpcChangesFilter,
        }
    },
}


def verify(event, _):
    try:
        standard_mapping = Cloudwatch_mappings[event["StandardLongName"]][
            event["StandardVersion"]
        ]
        return standard_mapping.get(event["ControlId"], None)
    except KeyError as ex:
        exit(
            f"ERROR: Could not find associated metric filter. Missing parameter: {str(ex)}"
        )

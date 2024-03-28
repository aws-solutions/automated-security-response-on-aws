# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation.autoscaling import run_autoscaling_1
from simtest.remediation.aws_lambda import run_make_lambda_private
from simtest.remediation.cloudtrail import (
    run_create_cloudtrail_multi_region_trail,
    run_create_ct_access_logging,
    run_create_multi_region_cloudtrail,
    run_enable_cloudtrail_logfile_validation,
    run_enable_ct_encryption,
    run_log_cloudtrail_to_cloudwatch,
    run_make_cloudtrail_s3_bucket_private,
)
from simtest.remediation.cloudwatch import run_log_and_filter
from simtest.remediation.config import run_setup_config
from simtest.remediation.ec2 import (
    run_close_default_sg,
    run_disable_public_access_for_security_group,
    run_enable_ebs_encryption_by_default,
    run_remove_public_ec2_snaps,
    run_remove_vpc_default_security_group_rules,
)
from simtest.remediation.guardduty import run_guardduty_1
from simtest.remediation.iam import (
    run_remove_old_credentials,
    run_revoke_unrotated_keys,
    run_set_password_policy,
)
from simtest.remediation.kms import run_setup_key_rotation
from simtest.remediation.rds import (
    run_enable_enhanced_monitoring_on_rds_instance,
    run_enable_rds_cluster_deletion_protection,
    run_make_rds_snapshot_private,
)
from simtest.remediation.s3 import (
    run_s3_block_public_access,
    run_s3_block_public_bucket_access,
)
from simtest.remediation.vpc import run_enable_vpc_flow_logs

# CIS 1.3 - 1.4
#     [CIS.1.3] Ensure credentials unused for 90 days or greater are disabled
#     [CIS.1.4] Ensure access keys are rotated every 90 days or less


def setup_cis13(account, region):
    run_remove_old_credentials("cis13", account, region)


def setup_afsbp_iam_8(account, region):
    run_remove_old_credentials("afsbp-iam.8", account, region)


def setup_pci_iam_7(account, region):
    run_remove_old_credentials("pci-iam.7", account, region)


def setup_cis14(account, region):
    run_revoke_unrotated_keys("cis14", account, region)


def setup_afsbp_iam_3(account, region):
    run_revoke_unrotated_keys("afsbp-iam.3", account, region)


# CIS 1.5 - 1.11
#     [CIS.1.5] Ensure IAM password policy requires at least one uppercase letter
#     [CIS.1.6] Ensure IAM password policy requires at least one lowercase letter
#     [CIS.1.7] Ensure IAM password policy requires at least one symbol
#     [CIS.1.8] Ensure IAM password policy requires at least one number
#     [CIS.1.9] Ensure IAM password policy requires minimum password length of 14 or greater
#     [CIS.1.10] Ensure IAM password policy prevents password reuse
#     [CIS.1.11] Ensure IAM password policy expires passwords within 90 days or less
def setup_cis15(account, region):
    run_set_password_policy("cis15111", account, region)


def setup_afsbp_iam_7(account, region):
    run_set_password_policy("afsbp-iam.7", account, region)


def setup_pci_iam_8(account, region):
    run_set_password_policy("pci-iam.8", account, region)


# CIS 2.1
#
def setup_cis21(account, region):
    run_create_multi_region_cloudtrail("cis21", account, region)


def setup_afsbp_cloudtrail_1(account, region):
    run_create_multi_region_cloudtrail("afsbp-cloudtrail.1", account, region)


def setup_pci_cloudtrail_2(account, region):
    run_create_multi_region_cloudtrail("pci-cloudtrail.2", account, region)


# CIS 2.2
#     [CIS.2.2] Ensure CloudTrail log file validation is enabled
#
def setup_cis22(account, region):
    run_enable_cloudtrail_logfile_validation("cis22", account, region)


def setup_pci_cloudtrail_3(account, region):
    run_enable_cloudtrail_logfile_validation("pci-cloudtrail.3", account, region)


# CIS 2.3
#     [CIS.2.3] Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
#
# Setting a bucket up for public access will generate a sev 2 TT and escalation to your manager.
# Let's not go there.
def setup_cis23(account, region):
    run_make_cloudtrail_s3_bucket_private("cis23", account, region)


# CIS 2.4
#     [CIS.2.4] Ensure CloudTrail trails are integrated with CloudWatch Logs
def setup_cis24(account, region):
    run_log_cloudtrail_to_cloudwatch("cis24", account, region)


def setup_pci_cloudtrail_4(account, region):
    run_log_cloudtrail_to_cloudwatch("pci-cloudtrail.4", account, region)


# CIS 2.6
#     [CIS.2.6] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
def setup_cis26(account, region):
    run_create_ct_access_logging("cis26", account, region)


# CIS 2.8
#     [CIS.2.8] Ensure rotation for customer created CMKs is enabled
def setup_cis28(account, region):
    run_setup_key_rotation("cis28", account, region)


# CIS 2.9
#     [CIS.2.9] Ensure VPC flow logging is enabled in all VPCs
def setup_cis29(account, region):
    run_enable_vpc_flow_logs("cis29", account, region)


def setup_afsbp_ec2_6(account, region):
    run_enable_vpc_flow_logs("afsbp-ec2.6", account, region)


def setup_pci_ec2_6(account, region):
    run_enable_vpc_flow_logs("pci-ec2.6", account, region)


# CIS 3.1-3.14
def setup_cis31314(account, region):
    run_log_and_filter("cis32", account, region)


def setup_pci_cw_1(account, region):
    run_log_and_filter("pci-cw.1", account, region)


# CIS 4.1 - 4.2
#     [CIS.4.1] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
#     [CIS.4.2] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
def setup_cis4142(account, region):
    run_disable_public_access_for_security_group("cis4142", account, region)


# CIS 4.3
#     [CIS.4.3] Ensure the default security group of every VPC restricts all traffic
def setup_cis43(account, region):
    run_remove_vpc_default_security_group_rules("cis43", account, region)


# AFSBP AutoScaling.1
#     [AFSBP.AutoScaling.1] Auto scaling groups associated with a load balancer should use load balancer health checks
def setup_afsbp_autoscaling_1(account, region):
    run_autoscaling_1("afsbp-autoscaling.1", account, region)


def setup_pci_autoscaling_1(account, region):
    run_autoscaling_1("pci-autoscaling.1", account, region)


# AFSBP CloudTrail.1
#     [AFSBP.CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-region trail
def setup_afsbp_cloudtrail_1x(account, region):
    run_create_cloudtrail_multi_region_trail("afsbp-cloudtrail.1", account, region)


# AFSBP CloudTrail.2
#     [AFSBP.CloudTrail.2] CloudTrail should have encryption at-rest enabled


def setup_cis27(account, region):
    run_enable_ct_encryption("cis27", account, region)


def setup_afsbp_cloudtrail_2(account, region):
    run_enable_ct_encryption("afsbp-cloudtrail.2", account, region)


def setup_pci_cloudtrail_1(account, region):
    run_enable_ct_encryption("pci-cloudtrail.1", account, region)


# AFSBP Config.1
#     [AFSBP.Config.1] AWS Config should be enabled
def setup_cis25(account, region):
    run_setup_config("cis25", account, region)


def setup_afsbp_config_1(account, region):
    run_setup_config("afsbp-config.1", account, region)


def setup_pci_config_1(account, region):
    run_setup_config("pci-config.1", account, region)


# AFSBP EC2.1
#     [AFSBP.EC2.1] EBS snapshots should not be public
def setup_afsbp_ec2_1(account, region):
    run_remove_public_ec2_snaps("afsbp-ec2.1", account, region)


def setup_pci_ec2_1(account, region):
    run_remove_public_ec2_snaps("pci-ec2.1", account, region)


# AFSBP EC2.2
#     [AFSBP.EC2.2] The VPC default security group should not allow inbound and outbound traffic
def setup_afsbp_ec2_2(account, region):
    run_close_default_sg("afsbp-ec2.2", account, region)


def setup_pci_ec2_2(account, region):
    run_close_default_sg("pci-ec2.2", account, region)


# AFSBP EC2.7
#     [AFSBP.EC2.7] The VPC default security group should not allow inbound and outbound traffic
def setup_afsbp_ec2_7(account, region):
    run_enable_ebs_encryption_by_default("afsbp-ec2.7", account, region)


# AFSBP GuardDuty.1
#     [AFSBP.GuardDuty.1] GuardDuty should be enabled
def setup_afsbp_guardduty_1(account, region):
    run_guardduty_1("afsbp-guardduty.1", account, region)


#
# AFSBP Lambda.1
#     [AFSBP.Lambda.1] Lambda function policies should prohibit public access
def setup_pci_lambda_1(account, region):
    run_make_lambda_private("pci-lambda.1", account, region)


def setup_afsbp_lambda_1(account, region):
    run_make_lambda_private("afsbp-lambda.1", account, region)


# AFSBP RDS.1
#     [AFSBP.RDS.1] RDS snapshot should be private
def setup_afsbp_rds_1(account, region):
    run_make_rds_snapshot_private("afsbp-rds.1", account, region)


def setup_pci_rds_1(account, region):
    run_make_rds_snapshot_private("pci-rds.1", account, region)


# AFSBP RDS.6
#     [AFSBP.RDS.6] Enhanced monitoring should be configured for RDS DB instance
def setup_afsbp_rds_6(account, region):
    run_enable_enhanced_monitoring_on_rds_instance("afsbp-rds.6", account, region)


# AFSBP RDS.7
#     [AFSBP.RDS.7] RDS clusters should have deletion protection enabled
def setup_afsbp_rds_7(account, region):
    run_enable_rds_cluster_deletion_protection("afsbp-rds.7", account, region)


# AFSBP S3.1 / PCI S3.6
def setup_afsbp_s3_1(account, region):
    run_s3_block_public_access("afsbp-s3.1", account, region)


def setup_pci_s3_6(account, region):
    run_s3_block_public_access("pci-s3.6", account, region)


# AFSBP S3.2-S3.3 / PCI S3.1-S3.2
def setup_afsbp_s3_2(account, region):
    run_s3_block_public_bucket_access("afsbp-s3.2", account, region)


def setup_pci_s3_2(account, region):
    run_s3_block_public_bucket_access("pci-s3.2", account, region)


testIdByStandard = {
    "afsbp": {
        "autoscaling.1": setup_afsbp_autoscaling_1,
        "cloudtrail.1": setup_afsbp_cloudtrail_1,
        "cloudtrail.2": setup_afsbp_cloudtrail_2,
        "config.1": setup_afsbp_config_1,
        "ec2.1": setup_afsbp_ec2_1,
        "ec2.2": setup_afsbp_ec2_2,
        "ec2.6": setup_afsbp_ec2_6,
        "ec2.7": setup_afsbp_ec2_7,
        "iam.3": setup_afsbp_iam_3,
        "iam.7": setup_afsbp_iam_7,
        "iam.8": setup_afsbp_iam_8,
        "lambda.1": setup_afsbp_lambda_1,
        "rds.1": setup_afsbp_rds_1,
        "rds.6": setup_afsbp_rds_6,
        "rds.7": setup_afsbp_rds_7,
        "s3.1": setup_afsbp_s3_1,
        "s3.2": setup_afsbp_s3_2,
    },
    "cis": {
        "1.3": setup_cis13,
        "1.4": setup_cis14,
        "1.5": setup_cis15,
        "2.1": setup_cis21,
        "2.2": setup_cis22,
        "2.3": setup_cis23,
        "2.4": setup_cis24,
        "2.5": setup_cis25,
        "2.6": setup_cis26,
        "2.7": setup_cis27,
        "2.8": setup_cis28,
        "2.9": setup_cis29,
        "3.1": setup_cis31314,
        "4.1": setup_cis4142,
        "4.3": setup_cis43,
    },
    "pci": {
        "autoscaling.1": setup_pci_autoscaling_1,
        "cloudtrail.1": setup_pci_cloudtrail_1,
        "cloudtrail.2": setup_pci_cloudtrail_2,
        "cloudtrail.3": setup_pci_cloudtrail_3,
        "cloudtrail.4": setup_pci_cloudtrail_4,
        "config.1": setup_pci_config_1,
        "cw.1": setup_pci_cw_1,
        "ec2.1": setup_pci_ec2_1,
        "ec2.2": setup_pci_ec2_2,
        "ec2.6": setup_pci_ec2_6,
        "iam.7": setup_pci_iam_7,
        "iam.8": setup_pci_iam_8,
        "lambda.1": setup_pci_lambda_1,
        "rds.1": setup_pci_rds_1,
        "s3.2": setup_pci_s3_2,
        "s3.6": setup_pci_s3_6,
    },
}

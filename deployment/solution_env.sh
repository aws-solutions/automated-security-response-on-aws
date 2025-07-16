#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
export SOLUTION_ID='SO0111'
export SOLUTION_NAME='Automated Security Response on AWS'
export SOLUTION_TRADEMARKEDNAME='automated-security-response-on-aws'
# The following are estimations for the max number of remediation runbooks to reach the template size limit.
# Adjust these values as needed, depending on the template size as more remediations are added.
export SC_MEMBER_STACK_LIMIT=85
export NIST_MEMBER_STACK_LIMIT=63
export AFSBP_MEMBER_STACK_LIMIT=63
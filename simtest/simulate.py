#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import argparse
import os

from simtest.boto_session import create_session
from simtest.controls import testIdByStandard
from simtest.orchestrator import create_orchestrator


def main():
    args = create_argument_parser().parse_args()
    resolve_missing_args(args)

    create_session(get_profile(), args.region)
    create_orchestrator(args.orch_region)

    initiate_remediation(args.standard, args.remediation, args.account, args.region)


def get_profile():
    try:
        return os.environ["AWS_PROFILE"]
    except Exception as e:
        print(e)
        usage()
        exit()


def usage():
    print(
        "Run this after assuming role (using isengardcli) in the Security Hub Administor account. Use isengardcli credentials to get temporary credentials before running this script"
    )


def initiate_remediation(standard, control, account, region):
    if control in testIdByStandard[standard]:
        print("-" * 80)
        print(f"Testing {standard} {control}")
        testIdByStandard[standard][control](account, region)
        print("\nRemediation was initiated. Verify that it completed successfully.\n")
    else:
        print("Remediation invalid: " + control)


def resolve_missing_args(args):
    if not args.account:
        args.account = os.getenv("sim_account", None)

    if not args.account:
        args.account = input("Account ID to test? ")

    if not args.standard:
        args.standard = input("Security Standard to test? ")

    if not args.region:
        args.region = args.orch_region


def create_argument_parser():
    argument_parser = argparse.ArgumentParser()

    argument_parser.add_argument(
        "--region",
        "-r",
        required=True,
        dest="orch_region",
        help="Region where findings are to be sent.",
    )
    argument_parser.add_argument(
        "--standard", "-s", required=True, help="Security Standard (cis, afsbp, or pci)"
    )
    argument_parser.add_argument(
        "--control",
        "-c",
        required=True,
        dest="remediation",
        help="Control to test. Ex. 2.9",
    )
    argument_parser.add_argument(
        "--account", "-a", required=False, help="Account to test"
    )
    argument_parser.add_argument(
        "--finding-region",
        "-f",
        required=False,
        dest="region",
        help="Region in which finding is to be remediated. Defaults to --region",
    )

    return argument_parser


if __name__ == "__main__":
    main()

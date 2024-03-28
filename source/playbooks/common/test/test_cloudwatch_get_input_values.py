# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest
from cloudwatch_get_input_values import routeTableChangesFilter, verify


def expected():
    return routeTableChangesFilter


def test_verifyCIS120():
    assert (
        verify(
            {
                "ControlId": "3.13",
                "StandardLongName": "cis-aws-foundations-benchmark",
                "StandardVersion": "1.2.0",
            },
            {},
        )
        == expected()
    )


def test_verifyCIS140():
    assert (
        verify(
            {
                "ControlId": "4.13",
                "StandardLongName": "cis-aws-foundations-benchmark",
                "StandardVersion": "1.4.0",
            },
            {},
        )
        == expected()
    )


def test_verifySC():
    assert (
        verify(
            {
                "ControlId": "CloudWatch.13",
                "StandardLongName": "security-control",
                "StandardVersion": "2.0.0",
            },
            {},
        )
        == expected()
    )


def test_failNoStandard():
    with pytest.raises(SystemExit) as response:
        verify({"ControlId": "3.13"}, {})

    assert (
        response.value.code
        == "ERROR: Could not find associated metric filter. Missing parameter: 'StandardLongName'"
    )

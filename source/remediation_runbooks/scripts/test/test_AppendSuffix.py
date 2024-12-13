# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from AppendSuffix import append_suffix


def test_append_suffix():
    event = {
        "OriginalString": "original_string",
        "MaxLen": 255,
        "Suffix": "suffix",
    }

    new_string = append_suffix(event, None)

    assert new_string == "original_stringsuffix"


def test_append_string_longer_than_max():
    event = {
        "OriginalString": "1234567890",
        "MaxLen": 10,
        "Suffix": "suffix",
    }

    new_string = append_suffix(event, None)

    assert new_string == "1234suffix"

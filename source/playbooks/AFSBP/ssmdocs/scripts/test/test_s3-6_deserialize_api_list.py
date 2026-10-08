# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import deserializeApiList as script
import pytest


def event():
    return {
        "SerializedList": '{"blacklistedActionPattern":"s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration"}'
    }


def expected():
    return "s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration"


def test_extract_list():
    assert script.runbook_handler(event(), {}) == expected()


def test_rollback_skips_extraction():
    # Annotated because dict is invariant: an inferred dict[str, str] is not a dict[str, object].
    rollback_event: dict[str, object] = {
        "SerializedList": "{{ ParseInput.DenyListSerialized }}",
        "Rollback": "ROLLBACK",
    }
    assert script.runbook_handler(rollback_event, {}) == ""


def test_rollback_flag_absent_or_empty_still_extracts():
    assert script.runbook_handler({**event(), "Rollback": ""}, {}) == expected()
    assert script.runbook_handler(event(), {}) == expected()


def test_malformed_list_raises_value_error_on_remediation_path():
    # Consistent with the other two failure modes in this handler: previously this path called exit(),
    # raising SystemExit, and printed the parse error instead of reporting it.
    with pytest.raises(ValueError, match="not valid JSON") as raised:
        script.runbook_handler({"SerializedList": "not-json", "Rollback": ""}, {})
    # The underlying parse error is preserved rather than printed and discarded.
    assert isinstance(raised.value.__cause__, json.JSONDecodeError)


def test_missing_serialized_list_raises_value_error():
    with pytest.raises(ValueError, match="SerializedList"):
        script.runbook_handler({"Rollback": ""}, {})
    with pytest.raises(ValueError, match="SerializedList"):
        script.runbook_handler({"SerializedList": "", "Rollback": ""}, {})


def test_missing_pattern_raises_value_error():
    with pytest.raises(ValueError, match="blacklistedActionPattern"):
        script.runbook_handler({"SerializedList": '{"other":"x"}', "Rollback": ""}, {})

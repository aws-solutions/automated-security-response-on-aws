# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from layer.simple_validation import clean_ssm, extract_safe_product_name, safe_ssm_path


def test_basic_cleaning():
    print("Testing basic cleaning:")

    # Test legitimate input
    result1 = clean_ssm("test-config")
    print(f'clean_ssm("test-config"): {result1}')
    assert result1 == "test-config"

    # Test malicious input
    result2 = clean_ssm("../../secrets")
    print(f'clean_ssm("../../secrets"): {result2}')
    assert result2 == "secrets"

    # Test slashes
    result3 = clean_ssm("test/with/slashes")
    print(f'clean_ssm("test/with/slashes"): {result3}')
    assert result3 == "test-with-slashes"

    # Test null bytes
    result4 = clean_ssm("test\x00malicious")
    print(f'clean_ssm("test\\x00malicious"): {result4}')
    assert result4 == "testmalicious"


def test_path_building():
    print("\nTesting path building:")

    result = safe_ssm_path("/Solutions/SO0111", "test-config")
    print(f'safe_ssm_path("/Solutions/SO0111", "test-config"): {result}')
    assert result == "/Solutions/SO0111/test-config"


def test_finding_extraction():
    print("\nTesting finding extraction:")

    # Legitimate finding
    config_finding = {"Title": "s3-bucket-public-access-prohibited"}
    result1 = extract_safe_product_name(config_finding, "Config")
    print(f'extract_safe_product_name(config_finding, "Config"): {result1}')
    assert result1 == "s3-bucket-public-access-prohibited"

    # Malicious finding
    malicious_finding = {"Title": "../../aws/secrets/database"}
    result2 = extract_safe_product_name(malicious_finding, "Config")
    print(f'extract_safe_product_name(malicious_finding, "Config"): {result2}')
    assert result2 == "aws-secrets-database"

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
from typing import Any, Dict, Optional


def clean_ssm(input_str: Optional[str]) -> str:
    if not input_str or not isinstance(input_str, str):
        return "unknown"

    cleaned = input_str.strip()

    # Remove path traversal patterns
    cleaned = cleaned.replace("..", "")
    cleaned = cleaned.replace("/", "-")
    cleaned = cleaned.replace("\\", "-")

    # Remove control characters that cause API failures
    cleaned = cleaned.replace("\x00", "")
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", cleaned)  # Control characters

    # Replace invalid characters with hyphens
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "-", cleaned)

    # Clean up leading/trailing special chars
    cleaned = cleaned.strip(".-_")

    # Ensure we have something meaningful
    if not cleaned or len(cleaned) < 2:
        return "unknown"

    return cleaned


def safe_ssm_path(base_path: str, product_name: str) -> str:
    cleaned_product_name = clean_ssm(product_name)
    return f"{base_path.rstrip('/')}/{cleaned_product_name}"


def extract_safe_product_name(finding_data: Dict[str, Any], product_name: str) -> str:
    component = None

    if product_name == "Config":
        component = finding_data.get("Title", "")
    elif product_name == "Health":
        component = finding_data.get("GeneratorId", "")
    elif product_name == "GuardDuty":
        types = finding_data.get("Types", [])
        if types and len(types) > 0:
            # Extract the finding type from the first type
            component = types[0].split("-")[-1] if "-" in types[0] else types[0]
    elif product_name == "Inspector":
        component = finding_data.get("ProductFields", {}).get(
            "attributes/RULE_TYPE", ""
        )
    else:
        # Fallback to Title for unknown products
        component = finding_data.get("Title", "")

    if not component:
        component = finding_data.get("Title", "")

    return clean_ssm(component)

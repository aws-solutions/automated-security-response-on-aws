# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# !/usr/bin/env python3

import json
import os
import re
import sys


def update_python_runtimes(directory):
    """
    The @cdklabs/cdk-ssm-documents package used to create some of the solution's control runbooks (SSM Documents)
    does not support python runtimes newer than python3.8 as of 11/14/2024. This function updates all member runbook templates
    to use python3.11 instead of python3.8 after they are synthesized.
    :param directory: directory where synthesized templates are located.
    """
    for template_filename in os.listdir(directory):
        if re.search(r"MemberStack(\d*).template$", template_filename):
            file_path = os.path.join(directory, template_filename)

            with open(file_path, "r") as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    print(f"Skipping {template_filename}: not a valid JSON file.")
                    continue
            # Convert template JSON to string and replace "python3.8" with "python3.11"
            template_str = json.dumps(data)
            updated_template_str = template_str.replace("python3.8", "python3.11")
            updated_template = json.loads(updated_template_str)
            # Write the updated template back to the .template file
            with open(file_path, "w") as file:
                json.dump(updated_template, file, indent=1)
            print(
                f"Successfully updated python runtimes in {template_filename} from python3.8 --> python3.11"
            )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Invalid invocation. Script should be invoked like: python upgrade_python_runtimes.py <directory_path>"
        )
        sys.exit(1)
    directory_path = sys.argv[1]
    update_python_runtimes(directory_path)

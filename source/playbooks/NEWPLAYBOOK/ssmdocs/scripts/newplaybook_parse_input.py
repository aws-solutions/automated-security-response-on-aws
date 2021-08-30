import re

def get_value_by_path(finding, path):
    path_levels = path.split('.')
    previous_level = finding
    for level in path_levels:
        this_level = previous_level.get(level)
        previous_level = this_level
    return this_level

def parse_event(event, context):
    expected_control_id = event['expected_control_id']
    parse_id_pattern = event['parse_id_pattern']
    resource_id_matches = []

    finding = event['Finding']

    finding_id = finding['Id']
    control_id = ''
    # Finding Id present and valid
    check_finding_id = re.match('^arn:(?:aws|aws-cn|aws-us-gov):securityhub:(?:[a-z]{2}(?:-gov)?-[a-z]+-\\d):\\d{12}:subscription/cis-aws-foundations-benchmark/v/1\\.2\\.0/(.*)/finding/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$',finding_id)

    if not check_finding_id:
        exit(f'ERROR: Finding Id is invalid: {finding_id}')
    else:
        control_id = check_finding_id.group(1)

    account_id = finding['AwsAccountId']
    if not re.match('^\\d{12}$', account_id):
        exit(f'ERROR: AwsAccountId is invalid: {account_id}')

    # ControlId present and valid
    if not control_id:
        exit(f'ERROR: Finding Id is invalid: {finding_id} - missing Control Id')

    # ControlId is the expected value
    if control_id not in expected_control_id:
        exit(f'ERROR: Control Id from input ({control_id}) does not match {str(expected_control_id)}')

    # ProductArn present and valid
    product_arn = finding['ProductArn']
    if not re.match('^arn:(?:aws|aws-cn|aws-us-gov):securityhub:(?:[a-z]{2}(?:-gov)?-[a-z]+-\\d)::product/aws/securityhub$', product_arn):
        exit(f'ERROR: ProductArn is invalid: {product_arn}')

    # ResourceType
    resource_type = finding['Resources'][0]['Type']

    # Regex match Id to get remediation-specific identifier
    identifier_raw = finding['Resources'][0]['Id']

    if parse_id_pattern:
        identifier_match = re.match(
            parse_id_pattern,
            identifier_raw
        )

        if not identifier_match:
            exit(f'ERROR: Invalid resource Id {identifier_raw}')
        else:
            for group in range(1, len(identifier_match.groups())+1):
                resource_id_matches.append(identifier_match.group(group))
            if 'resource_index' in event:
                resource_id = identifier_match.group(event['resource_index'])
            else:
                resource_id = identifier_match.group(1)
    else:
        resource_id = identifier_raw

    if not resource_id:
        exit('ERROR: Resource Id is missing from the finding json Resources (Id)')

    affected_object = {'Type': resource_type, 'Id': resource_id, 'OutputKey': 'Remediation.Output'}
    return {
        "account_id": account_id,
        "resource_id": resource_id, 
        "finding_id": finding_id, 
        "control_id": control_id,
        "product_arn": product_arn, 
        "object": affected_object,
        "matches": resource_id_matches
    }
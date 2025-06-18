## Test Data Stack
# WARNING:
* Deploying this stack will create intentionally insecure resources in your AWS environment. It is your responsibility to ensure these resources are not misused once deployed, and that they are kept isolated and are removed once no longer necessary.
### Prerequisites
You must have ASR deployed in a single account (admin + member). Choose a single playbook you would like to test.
### Description
This directory contains two stacks: `TestStack` & `RemediationResourcesStack`. The `RemediationResourcesStack` is a nested stack that creates the resources 
necessary to trigger Security Hub findings for all controls listed in the `common/controls.json` file. The `TestStack` deploys the `RemediationResourcesStack` along with
1 lambda-backed custom resource (`Custom::EnableRemediationRules`) and 1 Lambda function (ResetResourcesFunction) plus an EventBridge rule to trigger the ResetResourcesFunction Function on a schedule.
This schedule is determined by the CloudFormation parameter value entered at deployment time.

The `Custom::EnableRemediationRules` custom action is responsible for enabling all remediation rules for each control listed in the `common/controls.json` file. This allows the ASR remediations for these controls to be run automatically when Security Hub creates a finding.

The ResetResourcesFunction resets all the resources created by the `RemediationResourcesStack` to their respective unsafe states so that Security Hub will create a new finding for these resources. This function is triggered on a schedule determined at deployment time.

## Parameters
- `SecurityStandard`: The ASR playbook which you have deployed (Default: "SC")
- `SecurityStandardVersion`: The version associated with the ASR playbook you have deployed. You can find the standard version in the following file within the solution repository: source/playbooks/PLAYBOOK/bin/PLAYBOOK.ts (Default: "2.0.0")
- `RemediationFrequency`: The frequency in minutes that you wish to reset all testing resources to their unsafe state for continued remediation. 

### Deployment
To build and deploy the stacks with default parameters, run the following command:
- `cd test-stack && ./deploy-test-stack.sh`

To customize the parameters, copy & paste the following command into the build.sh:
- `cdk deploy TestStack --parameters SecurityStandard=YOUR_STANDARD SecurityStandardVersion=YOUR_VERSION RemediationFrequency=1440`

### Run Unit Tests
To run the unit tests for the lambda functions, run the following commands:
- `cd test-stack/lambda`
- `python -m pytest`

Note: you must have boto3, moto, and pytest installed.

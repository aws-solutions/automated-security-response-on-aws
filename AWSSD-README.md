## Table of Contents

- [Updating the Solution](#updating)
- [Playbook Structure](#playbooks)
- [Creating a Playbook](#creating)
- [Remediation Design - SHARR Runbooks](#remediation-design)

## Notes

### Use of Solution Id in Remediation Runbooks

The intent is to eventually publish remediation runbooks as AWS-owned documents. Therefore, they do not support use of Solution Id or Solution Version in user agent extra on API calls. Also, since we leverage SSM heavily and SSM executeAWSApi doesn't support this field, the use in some places but not others makes little sense.

<a name="updating"></a>
# Updating the Solution

## Update CDK Version
Ideally, the CDK version should be updated to the latest each time a new solution version is released. Use run-unit-tests.sh to verify that the snapshot still matches *prior to making any changes to the solution.*

1. Update package.json in the solution root: change all *old version* to *new version*
2. Change *required_cdk_version* in **deployment/build-s3-dist.sh** to the new version
3. Run build-s3-dist.sh, then run-unit-tests.sh. Verify that the snapshot matches. 

## Building and Deploying Locally
The solution configuration is in deployment/solution_env.sh. You should not need to change this file.

1) Create a global and a regional bucket for testing
ex. mybucket-reference and mybucket-us-east-1 (regional)
2) Check out the source from CodeCommit
3) cd to deployment
4) execute build-s3-dist.sh. -t DEVTEST instructs the build to prefix the Solution Id with "DEV-" to differentiate from production/customer deployments in solution metrics.

```
build-s3-dist.sh -b <bucket> -v <version> -t DEVTEST
```

5) use upload-s3-dist.sh to upload the build to your buckets (ex. "us-east-1")

```
upload-s3-dist.sh <region>
```

6) Use CloudFormation to deploy from the "reference" bucket (ex. "mybucket-reference")

<a name="playbooks"></a>
# Playbook Structure

## SHARR v1.2+ Architecture

* Uses SSM runbooks. Follow prescription for creating runbook structure and storing runbook yaml files.
* Uses same version_description.txt, support.txt, and README.md files as v1.0.
* An "Orchestration" Step Function recieves findings via CloudWatch Event Rules, determines the runbook to execute in the target account, executes and monitors the runbook execution.

## Playbook Folders
<pre>
|-playbookname/
|---bin/                  		[ CDK file for template creation ]
|---ssmdocs/                 	[ Runbook source ]
|-----scripts/					[ Runbook scripts ]
|-------test/					[ Pytest unit tests ]
|---test/                    	[ CDK test cases ]
|---description.txt				[ Description used for the playbook in Service Catalog ]
|---README.md                   [ Playbook README file ]
|---support.txt					[ For Service Catalog ]
|---version_description.txt		[ Desribes current playbook version ]
</pre>

<a name="creating"></a>
# Creating a New Playbook

## Adding a Playbook

SHARR v1.2 and later use a Step Function in the Admin account to validates inputs, extract finding data, and execute the target remediation using Systems Manager Runbooks in the member account. These are referred to as "SHARR Runbooks."

The logic is simple and extensible: a CloudWatch Event Rule matches findings and sends them to the Orchestrator Step Function. The Step Function extracts the control Id and uses it to derive the target SHARR Runbook algorithmically - there is no mapping, no if-then-else logic, and therefore nothing to add or update to introduce a new remediation.

Security is **Job 0**. SHARR Runbooks must be tightly secured, validate inputs, and have least-privilege access to **Remediation Runbooks**: runbooks that execute the actual remediation actions. This division of security and function allows for sharing of a remediation action for common controls that exist in more than one standard. SHARR Runbooks should not remediate directly, but use Remediation Runbooks.

**Remediation Runbooks** are AWS-owned or SHARR-owned runbooks that perform a single remediation or remediation step for a specific resource. For example, creating a logging bucket, enabling an AWS Service, or setting a parameter on an AWS Service. The permissions to the service APIs are within the definition of the Remediation Runbook; SHARR Runbooks must be allowed to assume the remediation role.

A playbook is a set of remediations within a Security Standard (ex. "CIS", "FSBP"). Each Playbook has a standard-specific Step Function ("Orchestrator") that "understands" the JSON format of that standard's Finding data. The Orchestrator does the following:
1. Verify the finding data matches the Standard (ex. CIS, PCI, FSBP)
2. Identify the control id and target account in the JSON data
3. Derive the runbook name (SHARR-\<standard\>-\<version\>-\<controlid\>)
4. Check the status of the runbook in the target account
5. Execute the runbook
6. Monitor until completion
7. Log execution data and send notifications.

### To create a new Playbook

A sample Playbook is provided as a starting point. The estimated time to create a new playbook with a single remediation is 4 or more hours. Each remediation thereafter will take one or more hours, depending upon whether the remediation runbook already exists.

#### Preconditions
* The Security Standard exists and is supported in AWS Security Hub
* The developer has access to AWS Security Hub to generate Finding json for test cases
* The Security Standard has been enabled AWS Security Hub in the account

#### Create the Definitions

1. Get the long name, short name, and version of the security standard from Security Hub by examining a finding for the Security Standard. It is extremely important that these values match the StandardControlArn in the finding data for the Security Standard, except for securityStandardShortName, which is an abbreviation you choose.
	
	Ex. *AWS Foundational Security Best Practices*
	
	* **StandardControlArn**: arn:aws:securityhub:us-east-1:111111111111:control/aws-foundational-security-best-practices/v/1.0.0/RDS.1
	* **securityStandardLongName**: aws-foundational-security-best-practices
	* **securityStandardShortName**: FSBP (can be any value you choose)
	* **version**: 1.0.0
	
	For the following example, we will create a PCI DSS v3.2.1 Playbook:
	
	* **StandardControlArn**: arn:aws:securityhub:us-east-1:111111111111:control/pci-dss/v/3.2.1/PCI.IAM.6
	* **securityStandardLongName**: pci-dss
	* **securityStandardShortName**: PCI
	* **version**: 3.2.1

2. Copy source/playbooks/NEWPLAYBOOK to a folder whose name is the short name and version (sans '.'s) concatenated. For our example, PCI321:

	```
	cd source/playbooks
	cp -R NEWPLAYBOOK PCI321
	cd PCI321
	```

3. rename files in **bin** and **lib**. 
	* bin/newplaybook.ts -> pci321.ts
	* lib/newplaybook-member-stack.ts -> pci321-member-stack.ts
	* lib/newplaybook-primary-stack.ts -> pci321-primary.stack.ts
	* test/newplaybook_stack.test.ts -> pci321_stack.test.ts

4. Edit ./bin/\<playbook\>.ts - ex. afsbp.ts
  	* Add environmental variables and description.
	* Change all "NEWPLAYBOOK" names to something specific to the new playbook. Consistency is key. Include the version if there is a possbility of supported more than one version concurrently (ex. 'PCI321' rather than 'PCI')
	* Set the Security Standard parameters for the standard:

		```
		const standardShortName = 'PCI'
		const standardLongName = 'pci-dss'
		const standardVersion = '3.2.1' # DO NOT INCLUDE 'V'
		```
	* In the *remediations* stringlist will go a list of Control Ids for which you are creating remedations. These Control Ids must match the ControlId from the **StandardControlArn** in the Finding data (more on this in **Runbooks**) Ex. **PCI.IAM.6**

		> Note: Until the ssmdocs for each control are created the stack will fail to build. You may wish to comment any out that you have not yet created.
		
	##### Example Playbook Definition
	
	```
	#!/usr/bin/env node
	/*****************************************************************************
	 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
	 *                                                                            *
	 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
	 *  not use this file except in compliance with the License. A copy of the    *
	 *  License is located at                                                     *
	 *                                                                            *
	 *      http://www.apache.org/licenses/LICENSE-2.0                            *
	 *                                                                            *
	 *  or in the 'license' file accompanying this file. This file is distributed *
	 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
	 *  express or implied. See the License for the specific language governing   *
	 *  permissions and limitations under the License.                            *
	 *****************************************************************************/
	import 'source-map-support/register';
	import * as cdk from '@aws-cdk/core';
	import {  PlaybookPrimaryStack, PlaybookMemberStack  } from '../../../lib/sharrplaybook-construct';
	
	// SOLUTION_* - set by solution_env.sh
	const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
	const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
	// DIST_* - set by build-s3-dist.sh
	const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
	const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
	const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';
	
	const standardShortName = 'FSBP'
	const standardLongName = 'aws-foundational-security-best-practices'
	const standardVersion = '1.0.0' // DO NOT INCLUDE 'V'
	const RESOURCE_PREFIX = SOLUTION_ID.replace(/^DEV-/,''); // prefix on every resource name
	
	const app = new cdk.App();
	
	// Creates one rule per control Id. The Step Function determines what document to run based on
	// Security Standard and Control Id. See afsbp-member-stack
	const remediations = [
		'AutoScaling.1',
		'CloudTrail.1',
		'CloudTrail.2',
		'Config.1',
		'EC2.1',
		'EC2.2',
		'EC2.6',
		'EC2.7',
		'IAM.7',
		'IAM.8',
		'Lambda.1',
		'RDS.1',
		'RDS.6',
		'RDS.7',
    'S3.9'
	]
	
	const adminStack = new PlaybookPrimaryStack(app, 'FSBPStack', {
		description: `(${SOLUTION_ID}P) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${DIST_VERSION}`,
		solutionId: SOLUTION_ID,
		solutionVersion: DIST_VERSION,
		solutionDistBucket: DIST_OUTPUT_BUCKET,
		solutionDistName: DIST_SOLUTION_NAME,
		remediations: remediations,
		securityStandardLongName: standardLongName,
		securityStandard: standardShortName,
		securityStandardVersion: standardVersion
	});
	
	const memberStack = new PlaybookMemberStack(app, 'FSBPMemberStack', {
		description: `(${SOLUTION_ID}C) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Member Account, ${DIST_VERSION}`,
		solutionId: SOLUTION_ID,
		solutionVersion: DIST_VERSION,
		solutionDistBucket: DIST_OUTPUT_BUCKET,
		securityStandard: standardShortName,
		securityStandardVersion: standardVersion,
		securityStandardLongName: standardLongName,
		remediations: remediations
	});
	
	adminStack.templateOptions.templateFormatVersion = "2010-09-09"
	memberStack.templateOptions.templateFormatVersion = "2010-09-09"
	```
	
5. Update test/pci321_stack.test.ts
6. Update cdk.json to point to the new bin/\*.ts name
7. ssmdocs/scripts parse script: the example should work for most Standards. Review what it does and make any adjustments.
8. Update the test script for the parse script. Copy finding json for the Security Standard to use in the test. See FSBP, CIS for examples.
10. Create the ssmdocs for each control in the ssmdocs folder. This is the runbook that is invoked directly by the Orchestrator.
11. Update support.txt, README.md, description.txt
12. Add the Playbook to source/jest.config.js

At this point you should be able to successfully run build-s3-dist.sh from the /deployment folder

### Create Runbooks

1. Using the provided example, create a runbook definition for each remediation
  * Runbook json files should be logically named
  * The Runbook they produce will be named SHARR-\<standard\>-\<version\>-\<control\>
  	 * standard: abbreviation for the standard. It must match the value for *standardShortName* in the CDK that defines the playbook
  	 * version: version of the standard in semver format. Ex. "1.0.0"
  	 * control: must match the value parsed from *StandardsControlArn* in the finding data.
2. If using executeScript your script code goes in ssmdocs/scripts. See **Using Scripts**
3. Create a parse_input script in ssmdocs/scripts for your finding

  * bin
  * lib
  * ssmdocs
  * test - typescript tests and data
3. Create the following files
  * cdk.json
  * description.txt - describes the playbook and appears in Service Catalog
  * README.md - readme file for the playbook
  * support.txt - support information to appear in Service Catalog
  * tsconfig.json
  * version_description.txt - describes this playbook version

<a name="remediation-design"></a>
# Remediation Design - SHARR Runbooks

SHARR Runbooks receive findings from the Orchestrator Step Function. Their role is to parse, validate, and route the finding data to a remediation runbook, and handle the Finding update. A SHARR runbook generally consists of 4 steps:

**ParseInput**: extracts the data required for the remediation from the finding and environment, determines the AffectedObject (subject of the remediation)
**ExecRemediation**: perform the remediation
**VerifyRemediation**: validate the remediation and post results to Output
**UpdateFinding**: Update the finding status

Note that ExecRemediation and VerifyRemediation can be combined in a single step. Be sure to make the output mapping correct for the step name.

## Design Notes
**NO ERROR HANDLING**
Let it fail. The Automation must fail in order to signal the Step Function. If the remediation handles the error, it must then cause the runbook to fail.
**VERIFY Actions**
If calling another runbook to perform the remediation, the parent remediation runbook should use the VerifyRemediation step to check the output returned by the child runbook.

If remediating directly, use judgement. If the API calls for remediation return an assertion of completion with verifiable data, use it. If not, perform active validation of the remediation.

## Inputs

  AutomationAssumeRole:
    type: String
    description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
    allowedPattern: ^arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/[\w+=,.@-]+
  Finding:
    type: StringMap
    description: The input from Step function for the finding

## Outputs
  - VerifyRemediation.Output
  - ParseInput.AffectedObject

Expected output must be in the Output for the Runbook.

## Scripts

When using *executeScript* actions, the source code for the remediation script is stored in playbooks/\<standard\>/ssmdocs/scripts in a file named \<standard\>_\<control\>_\<stepname\>.py. This allows the build pipeline to scan the script code, run unit tests, and supports syntax highlighting in the developer IDE vs. embedding hard-coded scripts in the SSM Doc's yaml/json definition. In place of the embedded code, place the following: %%SCRIPT=<scriptfile>%% as in the example below. This works syntantically with YAML, and although a blit kludgy, supports the required ability to scan, lint, and test the scripts.

```
 - name: ParseInput
    action: 'aws:executeScript'
    outputs:
      - Name: IAMUser
        Selector: $.Payload.iamuser
        Type: String
      - Name: FindingId
        Selector: $.Payload.finding_id
        Type: String
      - Name: ProductArn
        Selector: $.Payload.product_arn
        Type: String
      - Name: AffectedObject
        Selector: $.Payload.object
        Type: StringMap
    inputs:
      InputPayload:
        Finding: '{{Finding}}'
      Runtime: python3.7
      Handler: parse_event
      Script: |-
        %%SCRIPT=cis_1.3_parse_input.py%%
    isEnd: false
```

During the build-s3-dist.sh process, the CDK script will insert the script as inline code in the template, as there is currently no way to use attachments via CloudFormation without a Lambda-backed custom resource to create the automation document using the API (which does support it).

# Shared Remediations

In SHARR v1.3 we introduced shared remediations - remediation code that is separate from the security controls. SHARR remediation document names start with **SHARR-** and a name describing what the runbook does. Ex. **SHARR-CreateAccessLoggingBucket** creates a bucket for logging access to another bucket.

## Roles 

SO0111-<docname>

## Using AWSConfigRemediation AWS-Owned Documents

1. Find the document in the console
2. Go to Content tab
3. Copy the source
4. Save *unaltered* to the solution.

Note that these will be replaced with the AWS-Owned version once they are supported in GovCloud and China.

## Add it to the template

source/solution_deploy/lib/remediation_runbook-stack.ts

# Processing Runbook Output

**`check_ssm_execution.py`** is responsible for monitoring SHARR Parse Runbooks until they finish, determining the outcome, collecting and logging metrics and log data.

Runbook output (AutomationExecutionMetadataList Outputs) contains the output from the runbook. Parse runbooks must retrieve this data from child runbooks.

`check_ssm_execution.py` returns an answer json object:
```
{
	'status': string,
	'remediation_status': string,
	'message': string,
	'executionid': uuid,
	'affected_object': string,
	'logdata': serialized json
}
```

**status**

The state of the remediation execution. This is separate from **remediation\_status** - the runbook can succeed but remediation fail. Conversely, if the runbook failed, likely so did the remediation.

**remediation\_status**

The state of the remediation. This is separate from **status** - the runbook can succeed but remediation fail. Conversely, if the runbook failed, likely so did the remediation.

**message**

The message text to be sent in an SNS message and logs.

**executionid**

UUID of the AutomationExecution

**affected\_object**

\<type\> \<object\> when available, else string value of the affected object field from the step function.

**logdata**

Logdata comes from one or more of:

* AutomationExecution Outputs: Remediation.Output, VerifyRemediationOutput, or serialized json content of the Outputs field, in order of precedence.
* AutomationExecution FailureMessage

## From the Bottom

### Special Things

Remediation structure generally looks like this:

SHARR Remediation -> Remediation Runbook -> Scripts

SHARR Remediations are runbooks named per a defined standard that enables derivation of the name of the automation from the finding data: ```
SHARR-<standard>_<version>_<control>
```

Remediation Runbooks can be SHARR-owned or AWS-owned. For SHARR-owned, the solution completely controls the inputs and outputs. For AWS-owned, SHARR gets whatever the author has enabled.

Scripts for SHARR-owned documents are stored externally to the runbook yaml and assembled in the build. SHARR developers have complete control over their content.

#### Remediation.Output
Most SHARR runbooks have the following **outputs** declared. For consistency, make sure all remediation runbooks make their output available such that the SHARR remediation is able to retrieve meaningful log data. This must start from the very bottom.

```
outputs:
  - ParseInput.AffectedObject
  - Remediation.Output 
```

#### Failure

Remediation runbooks should fail when the remediation they perform fails. Testing success of the remediation then does not require checking an output field: if the runbook succeeded then the remediation step it performed succeeded.

Scripts support this by using python **exit** and a message. The message goes to the automation output in the console as well as the SHARR logs, so it must be concise and informative.

> Do not use **raise** to signal failure. Use **exit**.

### Child Runbook - SHARR-owned Remediation

* Runbook output is always in Output
* Scripts must write to stdout or return data

Output from a aws:executeScript includes **ExecutionLog** (stdout) and **Payload** (anything returned). ExecutionLog is newline-delimited.

```
{
	"ExecutionLog":"test returning via result
message from inside the function
",
	"Payload": {
		"result": {
			"message": "This is returned data set by the script",
			"status": "Success set by the script"
		}
	}
}
```

For child runbooks you must choose one or the other to map to Output.

#### Example with stdout
```
name: Remediation
    action: 'aws:executeScript'
    outputs:
      - Name: Output
        Selector: $.ExecutionLog
        Type: String
```

#### Example with return

```
name: Remediation
    action: 'aws:executeScript'
    outputs:
      - Name: Output
        Selector: $.Payload.result
        Type: String
```

Note that you can use both to make stdout and returned data available to later steps.

```
name: Remediation
    action: 'aws:executeScript'
    outputs:
      - Name: Stdout
        Selector: $.ExecutionLog
        Type: String
      - Name: Result
		Selector: $.Payload.result
        Type: String
```

### Child Runbook - AWS-owned

> As of v1.3.0, there are 88 AWS-owned runbooks named **AWSConfigRemediation-\*** that were written for the SSM Service Team. They are not yet available in US GovCloud or China. Any of these runbooks that are needed for remediations can be copied into source/remediation_runbooks. They will be installed as SHARR runbooks. Make no changes to the runbook code (other than bugfixes).

For AWS-owned runbooks you must examine the code to see what is stored in Output for the runbook. Generally, the check\_ssm\_execution lambda should recognize the output and place it appropriately-formatted in the logs.
# Permissions
Roles are copied per region by appending the region name to the role. This is because CloudFormation can't conditionally create a role, and when deploying in multiple regions the role names will collide unless something is added to differentiate them. Note also that role names must be derivable work cross-account, cross-region, and cross-stack, so dynamic naming is not an option.

## Orchestrator

There are two roles for the Orchestrator. One used by the step function, and one by the lambdas.

### Step Function Role
**Name:** SHARR-\<version\>-orchestratorRole\<hash\>

Allows actions performed directly by the step function.

### Lambda Roles
**Name:** SO0111-SHARR-Orchestrator-Admin_\<region\>

Statically-named role that allows cross-account and cross-region assume-role to SO0111-SHARR-Orchestrator-Member_\<region\> and all SO0111-Remediate-* roles, as well as access to Systems Manager Parameter Store Solutions/SO0111/* parameters.

This role is used by Lambdas **SO0111-SHARR-checkSSMDocState**, **SO0111-SHARR-execAutomation**, and **SO0111-SHARR-monitorSSMExecState**.

**Name:** SHARR-\<version\>-notifyRole\<hash\>

Used by SO0111-SHARR-sendNotifications Lambda function

### Runbook Roles

**Name:** SO0111-Remediate-\<standard\>-\<version\>-\<control\>_\<region\>

Statically-named (must be derivable) roles for SHARR Runbooks, which are the top-level runbook in member accounts. Their job is to parse the finding and perform remediation via remediation runbooks.

**Name:** SO0111-\<action\>_\<region\>

These roles allow the Orchestrator Admin role to assume/pass the role to remediation runbooks. They allow specific actions needed for remediation. Names are static as they must be derivable. The calling runbook specifies the role via the **AutomationAssumeRole** parameter.


# Appendix A - Runbook Standards
The Markdown in the Description for each SSM Document is displayed in the console as rendered Markdown. Attention to this section is important, as this impacts the customer's console experience.

## Parse Runbooks
"Parse Runbooks" receive the finding record from the Orchestrator and parse the data to get the identifiers needed for remediation. We prefix all Runbook names with **SHARR-**. Parse runbook names follow the standard 
```
SHARR-<standard>_<version>_<control>
```

* **standard**: abbreviation for the Security Standard. The abbreviation is set in an SSM Parameter, /**/Solutions/SO0111/<name>/<version/shortname**. For example, **/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname** = **FSBP**
* **version**: *v*.*r*.*m* - semver format version of the *Security Standard*. Some standards have multiple versions and may not be compatible with other versions.
* **control**: control Id within the standard. Ex. **2.1** (CIS), **CloudTrail.1** (FSBP)

### Example Document Names
* **SHARR-FSBP-v1.0.0-CloudTrail.1**
* **SHARR-CIS-v1.2.0-2.1**

### Header Template
```
### Document Name - SHARR-<standard>_<version>_<control>

## What does this document do?
<one or more lines briefly describing what it does>

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  
## Output Parameters
* Remediation.Output - Output of remediation runbooks.

[<standard> <version> <control>](<link to AWS Security Hub doc on this finding>)
```

### Example
``` 
### Document Name - SHARR-CIS_1.2.0_4.3

## What does this document do?
Removes public access from an EC2 Security Group for controls CIS 4.1 and CIS 4.2

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  
## Output Parameters
* Remediation.Output - Output of AWS-DisablePublicAccessForSecurityGroup runbook.

## Documentation Links
[CIS v1.2.0 4.3](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.3)
```

## Remediation Runbooks
Remediation runbooks often support more than one Control. They are called by the "Parse Runbooks." We prefix Remediation Runbook names with **SHARR-** to make them easily identifiable, but also to minimize name length.

**NOTE:** Remediation runbooks are designed with the intent of eventually becoming AWS-owned documents. Because SHARR remediations use a mix of executeAWSAPI, executeAutomation, and executeScript, user-agent-extra is not supported in remediation runbooks so that the calling runbook does not have to be concerned with whether the remediation runbooks it calls are AWS-owned or not, or whether or not it supports SolutionId and SolutionVersion.

### Header Template

```
  ### Document name - SHARR-<descriptive name>

  ## What does this document do?
  <one or more lines briefly describing what it does>
  
  ## Input Parameters
  * AutomationAssumeRole: (Required) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf.
  * <parameter>: <description>

  ## Output Parameters
  * Remediation.Output - stdout messages from the remediation

  ## Security Standards / Controls
  * <standard> <version> <control>
  * <standard> <version> <control>
  * ...
```

### Example Header

```
  ### Document name - SHARR-EnableAutoScalingGroupELBHealthCheck

  ## What does this document do?
  This runbook enables health checks for the Amazon EC2 Auto Scaling (Auto Scaling) group you specify using the [UpdateAutoScalingGroup](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_UpdateAutoScalingGroup.html) API.

  ## Input Parameters
  * AutomationAssumeRole: (Required) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf.
  * AutoScalingGroupARN: (Required) The Amazon Resource Name (ARN) of the auto scaling group that you want to enable health checks on.
  * HealthCheckGracePeriod: (Optional) The amount of time, in seconds, that Auto Scaling waits before checking the health status of an Amazon Elastic Compute Cloud (Amazon EC2) instance that has come into service.
  
  ## Output Parameters

  * Remediation.Output - stdout messages from the remediation

  ## Security Standards / Controls
  * FSBP v1.0.0:  Autoscaling.1
  * CIS v1.2.0:   2.1
  * PCI:          Autoscaling.1
```

# Appendix B - SSM Parameters
```
Solutions
	SO0111
		<standard name> - as it appears in the Finding StandardsControlArn
			shortname: string, value: 'cis'
			<version>
				status: ‘enabled’ or ‘disabled’
				<control>
					remap: string value of another control to execute. Ex. CIS 1.5-1.11 remap to 1.5
					<parameter>: string value of a control-specific parameter

```

Example:

```
Solutions
	SO0111
		cis-aws-foundations-benchmark
			shortname: cis
			1.2.0
				status: enabled
				controls:
					1.6:
						remap: 1.5
					3.1:
						alarm_threshold: 40
					3.2:
						remap: 3.1
						alarm_threshold: 10
						filter: 'abcdef'
```
						
# Appendix B - Publishing Checklist
## For Each Runbook:

- [ ] Runbook has markdown documentation as described in Appendix A
- [ ] UpdateFinding **UpdatedBy** has the correct name of the Parse Runbook (ex `SHARR-CIS_v1.2.0_2.1`)
- [ ] Runbook Markdown renders properly in the console
 

# Appendix C - Testing
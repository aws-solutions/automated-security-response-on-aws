// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
export class RegexTestCase {
  _regex: string;
  _description: string;
  _validTestStrings: string[];
  _invalidTestStrings: string[];
  _disabled: boolean;

  constructor(regex: string, description: string, validTestStrings: string[], invalidTestStrings: string[]) {
    // TODO disallow empty valid and invalid test strings arrays
    this._regex = regex;
    this._description = description;
    this._validTestStrings = validTestStrings;
    this._invalidTestStrings = invalidTestStrings;
    this._disabled = false;
  }

  getId(): string {
    return this._regex;
  }

  runTests() {
    if (this._disabled) {
      return;
    }
    const regex = new RegExp(this._regex);
    for (const testString of this._validTestStrings) {
      expect(testString).toMatch(regex);
    }
    for (const testString of this._invalidTestStrings) {
      expect(testString).not.toMatch(regex);
    }
  }

  disable() {
    this._disabled = true;
  }

  toString(): string {
    return this._regex;
  }
}

export class RegexMatchTestCase extends RegexTestCase {
  _matchTestCases: { testString: string; matches: string[] }[];

  constructor(regex: string, description: string, validTestStrings: string[], invalidTestStrings: string[]) {
    super(regex, description, validTestStrings, invalidTestStrings);
    this._matchTestCases = [];
  }

  runTests() {
    super.runTests();
    if (this._disabled) {
      return;
    }
    const regex = new RegExp(this._regex);
    for (const matchTestCase of this._matchTestCases) {
      expect(matchTestCase.testString).toMatch(regex);
      const actualMatches: string[] = regex.exec(matchTestCase.testString) || [];
      expect([matchTestCase.testString].concat(matchTestCase.matches)).toStrictEqual(Array.from(actualMatches));
    }
  }

  addMatchTestCase(testString: string, matches: string[]) {
    this._matchTestCases.push({ testString, matches });
  }
}

export class RegexRegistry {
  _cases: Map<string, RegexTestCase>;
  _regexForAutomationAssumeRole: string | undefined;

  constructor() {
    this._cases = new Map();
  }

  addCase(testCase: RegexTestCase) {
    const id: string = testCase.getId();
    if (this._cases.has(id)) {
      throw Error(`Test case already added for regex: ${id}`);
    }
    this._cases.set(id, testCase);
  }

  getAllCases(): RegexTestCase[] {
    return Array.from(this._cases.values());
  }

  setRegexForAutomationAssumeRole(regex: string) {
    this._regexForAutomationAssumeRole = regex;
  }

  getRegexForAutomationAssumeRole(): string {
    if (!this._regexForAutomationAssumeRole) {
      throw Error('No regex for AutomationAssumeRole');
    }
    return this._regexForAutomationAssumeRole || '';
  }

  has(regex: string): boolean {
    if (this._cases.has(regex)) {
      return true;
    } else {
      return false;
    }
  }
}

export function getRegexRegistry(): RegexRegistry {
  const registry: RegexRegistry = new RegexRegistry();

  const automationAssumeRoleRegex: string = String.raw`^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$`;
  registry.setRegexForAutomationAssumeRole(automationAssumeRoleRegex);

  // TODO: does not properly exclude names over 64 characters
  // TODO: does not properly include names with paths
  registry.addCase(
    new RegexTestCase(
      automationAssumeRoleRegex,
      'IAM Role ARN, no match',
      [
        'arn:aws:iam::111111111111:role/example-role',
        'arn:aws-us-gov:iam::111111111111:role/ValidRole',
        'arn:aws-cn:iam::111111111111:role/username@example.com',
        'arn:aws:iam::111111111111:role/_+=,.',
      ],
      [
        'arn:aws:iam::111111111111:role/',
        'art:aws:iam::111111111111:role/standard',
        'arn:aws-fictional-partition:iam::111111111111:role/otherwise-valid',
      ],
    ),
  );

  registry.addCase(
    new RegexTestCase(String.raw`^arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/[a-zA-Z0-9+=,.@_/-]+$`, 'IAM Role ARN', [], []),
  );

  registry.addCase(
    new RegexTestCase(String.raw`^[\w+=,.@-]{1,64}$`, 'IAM User Name', ['a-valid-user-name'], ['an invalid username']),
  );

  const kmsKeyArnTestCase: RegexTestCase = new RegexTestCase(
    String.raw`^arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(?:(?:alias/[A-Za-z0-9/-_])|(?:key/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})))$`,
    'KMS Key ARN as Key ID or Alias, no match',
    [],
    [],
  );
  // TODO: ES regex engine doesn't support case-insensitive non-capturing groups, just include capitals
  kmsKeyArnTestCase.disable();
  registry.addCase(kmsKeyArnTestCase);

  const kmsKeyArnOrIdOrAlias: RegexTestCase = new RegexTestCase(
    String.raw`^(?:arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:)?(?:(?:alias/[A-Za-z0-9/_-]+)|(?:key/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})))$`,
    'KMS Key ARN or Key ID or Alias, no match',
    ['alias/aws/rds'],
    [],
  );
  // TODO: ES regex engine doesn't support case-insensitive non-capturing groups, just include capitals
  kmsKeyArnOrIdOrAlias.disable();
  registry.addCase(kmsKeyArnOrIdOrAlias);

  registry.addCase(
    new RegexTestCase(
      String.raw`^[\w+=,.@-]+$`,
      'IAM Role name, no match',
      ['SO0111-RemediationRoleName'],
      ['Not:A:IAM:Role:Name'],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`^[\w+=,.@/-]+$`, 'IAM Role name with path, no match', [], []));

  registry.addCase(new RegexTestCase(String.raw`^(:?[\w+=,.@-]+/)+[\w+=,.@-]+$`, 'IAM role name', [], []));

  registry.addCase(new RegexTestCase(String.raw`^[\w+=,.@_-]{1,128}$`, 'Config unique identifier', [], []));

  registry.addCase(
    new RegexTestCase(
      String.raw`^$|^[a-zA-Z0-9/_-]{1,256}$`,
      'KMS Key Alias, no match',
      ['default-s3-encryption', 'sharr-test-key-alias'],
      ['asdf,vvv'],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`[a-z0-9-]{1,2048}`, 'KMS Key ID', [], []));

  registry.addCase(
    new RegexTestCase(
      String.raw`(?=^.{3,63}$)(?!^(\d+\.)+\d+$)(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)`,
      'S3 Bucket Name',
      ['replace-this-with-s3-bucket-name-for-audit-logging'],
      [],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`^[A-Za-z0-9][A-Za-z0-9\-_]{1,254}$`, 'CodeBuild project name', [], []));

  registry.addCase(new RegexTestCase(String.raw`^vpc-[0-9a-f]{8,17}`, 'VPC ID', [], []));

  registry.addCase(new RegexTestCase(String.raw`sg-[a-z0-9]+$`, 'Security group ID', [], []));

  registry.addCase(new RegexTestCase(String.raw`^[a-zA-Z0-9\-_]{1,64}$`, 'Lambda Function name', [], []));

  registry.addCase(new RegexTestCase(String.raw`^[0-9]{12}$`, 'Account ID', [], []));

  // TODO remove duplicate
  registry.addCase(new RegexTestCase(String.raw`^\d{12}$`, 'Account ID', [], []));

  registry.addCase(new RegexTestCase(String.raw`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`, 'Region Name', [], []));

  registry.addCase(new RegexTestCase(String.raw`^[a-zA-Z0-9-]{1,35}$`, 'RDS Cluster ID', [], []));
  registry.addCase(new RegexTestCase(String.raw`^cluster-[A-Z0-9]+$`, 'RDS DB Resource Cluster ID', [], []));

  registry.addCase(
    new RegexTestCase(
      String.raw`^db-[A-Z0-9]{26}$`,
      'RDS DB Resource ID',
      ['db-0123456789ABCDEFGHIJKLMNOP'],
      [
        '',
        'db',
        'db-DEADBEEF',
        'db-0123456789ABCDEFGHIJKLMNOPTOOLONG',
        'db-0123456789ABCDEF-HIJKLMNOP',
        'prefix-db-0123456789ABCDEFGHIJKLMNOP',
        'db-0123456789ABCDEFGHIJKLMNOP-suffix',
        'db-0123456789abcdefghijklmnop',
      ],
    ),
  );

  registry.addCase(
    new RegexTestCase(String.raw`^[a-zA-Z](?:[0-9a-zA-Z]+[-]{1})*[0-9a-zA-Z]{1,}$`, 'RDS DB Snapshot ID', [], []),
  );

  registry.addCase(
    new RegexTestCase(
      String.raw`^(?:rds:|awsbackup:)?(?!.*--.*)(?!.*-$)[a-zA-Z][a-zA-Z0-9-]{0,254}$`,
      'RDS DB Snapshot Name',
      [],
      [],
    ),
  );

  registry.addCase(
    new RegexTestCase(
      String.raw`^(?!.*--.*)(?!.*-$)[a-zA-Z][a-zA-Z0-9-]{0,254}$`,
      'RDS DB Snapshot Name, no automated snapshots',
      [],
      [],
    ),
  );

  registry.addCase(
    new RegexTestCase(
      String.raw`^(?!.*--)[a-zA-Z][a-zA-Z0-9.,$;-]{0,58}[^-]$`,
      'RDS DB Instance Identifier',
      ['database-1'],
      ['not--valid', 'notvalid--', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`^[A-Za-z0-9._-]{3,128}$`, 'CloudTrail Name', [], []));

  registry.addCase(
    new RegexTestCase(
      String.raw`(^arn:(aws[a-zA-Z-]*)?:cloudtrail:[a-z0-9-]+:\d{12}:trail\/(?![-_.])(?!.*[-_.]{2})(?!.*[-_.]$)(?!^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)[-\w.]{3,128}$)|(^(?![-_.])(?!.*[-_.]{2})(?!.*[-_.]$)(?!^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)[-\w.]{3,128}$)`,
      'CloudTrail Name or ARN',
      [],
      [],
    ),
  );

  registry.addCase(
    new RegexTestCase(
      String.raw`^arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:trail/[A-Za-z0-9._-]{3,128}$`,
      'CloudTrail ARN',
      [],
      [],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`^[a-zA-Z0-9-_./]{1,512}$`, 'CloudTrail Log Group Name', [], []));

  const autoScalingGroupNameTestCase: RegexTestCase = new RegexTestCase(
    String.raw`^.{1,255}$`,
    'AutoScaling Group Name',
    ['my-group'],
    ['', 'a'.repeat(256)],
  );
  registry.addCase(autoScalingGroupNameTestCase);

  registry.addCase(new RegexTestCase(String.raw`^[a-zA-Z0-9][a-zA-Z0-9-_]{0,255}$`, 'SNS Topic Name', [], []));
  registry.addCase(
    new RegexTestCase(
      String.raw`^arn:(?:aws|aws-us-gov|aws-cn):sns:[0-9a-zA-Z-]*:\d{12}:[a-zA-Z0-9-_]+$`,
      'SNS Topic Arn',
      [
        'arn:aws:sns:us-east-1:111122223333:SomeTopicName',
        'arn:aws-us-gov:sns:us-gov-east-1:111122223333:SomeTopicName',
      ],
      [],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`^(?:[1-9]\d{0,3}|10000)$`, 'Integer, [1, 10000]', ['90'], []));

  // TODO remove, this is ridiculous
  registry.addCase(
    new RegexTestCase(
      String.raw`^(\b([0-9]|[1-8][0-9]|9[0-9]|[1-8][0-9]{2}|9[0-8][0-9]|99[0-9]|[1-8][0-9]{3}|9[0-8][0-9]{2}|99[0-8][0-9]|999[0-9]|10000)\b)$`,
      'Integer, [1, 10000]',
      [],
      [],
    ),
  );

  registry.addCase(new RegexTestCase(String.raw`^[0-9]\d*$`, 'Integer', [], []));

  // TODO remove, this regex should not be used for validation
  registry.addCase(new RegexTestCase(String.raw`.*`, 'Any string', [], []));

  registry.addCase(
    new RegexTestCase(
      String.raw`^(?!.*--)[a-z][a-z0-9-]{0,62}(?<!-)$`,
      'Redshift Cluster Name',
      ['my-redshift-cluster-6', 'a'],
      [
        '1-invalid',
        '-also-invalid-6',
        'still--invalid',
        'again-invalid-6-',
        'too-long-cluster-name-too-long-too-long-cluster-name-too-long-23',
      ],
    ),
  );

  registry.addCase(
    new RegexTestCase(String.raw`^[^"'\\ ]{0,512}$`, 'The prefix applied to the log file names.', [], []),
  );

  registry.addCase(
    new RegexTestCase(
      String.raw`^(arn:(?:aws|aws-us-gov|aws-cn):cloudformation:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:stack/[a-zA-Z][a-zA-Z0-9-]{0,127}/[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})$`,
      'CloudFormation Stack ARN',
      ['arn:aws:cloudformation:us-east-1:111111111111:stack/my-stack/00000000-0000-0000-0000-000000000000'],
      [
        'arn:aws:cloudformation:us-east-1:111111111111:stack/bad_stack_name/00000000-0000-0000-0000-000000000000',
        'arn:aws:cloudformation:us-east-1:111111111111:stack/my-stack/bad_uuid',
      ],
    ),
  );

  registry.addCase(
    new RegexTestCase(
      String.raw`^[a-zA-Z0-9_-]{1,80}(?:\.fifo)?$`,
      'SQS Queue name',
      ['a_real_queue'],
      ['a.bad.queue'],
    ),
  );

  registry.addCase(
    new RegexTestCase(String.raw`^(?:[0-9]|[1-9][0-9]|100)$`, 'Number 0-100', ['0', '100', '27'], ['011']),
  );

  addIamMatchTestCases(registry);
  addAutoScalingMatchTestCases(registry);
  addCloudTrailMatchTestCases(registry);
  addCodeBuildMatchTestCases(registry);
  addEc2MatchTestCases(registry);
  addLambdaMatchTestCases(registry);
  addRdsMatchTestCases(registry);
  addS3MatchTestCases(registry);
  addKmsMatchTestCases(registry);
  addRedshiftMatchTestCases(registry);
  addSNSMatchTestCases(registry);
  addSQSMatchTestCases(registry);
  addEC2InstanceMatchTestCases(registry);
  addEC2InstanceIdMatchTestCases(registry);
  addECRRepositoryMatchTestCases(registry);
  addECRRepositoryARNMatchTestCases(registry);
  addCloudFrontMatchTestCases(registry);
  addCloudFrontDefaultObjectTestCases(registry);
  addCloudFrontMatchTestCasesAlternative(registry);
  addCloudFrontDistributionIdTestCases(registry);
  addSSMDocumentArnTestCases(registry);
  addTransitGatewayIdTestCases(registry);
  addTransitGatewayARNTestCases(registry);
  addSecretsManagerArnTestCases(registry);

  return registry;
}

function addIamMatchTestCases(registry: RegexRegistry) {
  const iamUserTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:user(?:(?:\u002F)|(?:\u002F[\u0021-\u007F]{1,510}\u002F))([\w+=,.@-]{1,64})$`,
    'IAM User ARN, capture User Name',
    [
      'arn:aws:iam::111111111111:user/aUser',
      'arn:aws-us-gov:iam::111111111111:user/99_special-characters@example.com',
      'arn:aws-cn:iam::111111111111:user/with/path/Alice',
      'arn:aws:iam::111111111111:user///.',
    ],
    [
      'arn:aws:iam::111111111111:role/ActuallyARole',
      'arn:aws:iam::111111111111:user//SuprisinglyInvalid',
      'arn:aws:iam::111111111111:user/AUsernameThatIsJustTooLongPleaseReconsiderCreatingUsernamesThisLong',
      `arn:aws:iam::111111111111:user/${'_'.repeat(511)}/PathTooLong`,
    ],
  );
  iamUserTestCase.addMatchTestCase('arn:aws:iam::111111111111:user/TestUser', ['TestUser']);
  iamUserTestCase.addMatchTestCase('arn:aws-us-gov:iam::111111111111:user/with/path/user@example.com', [
    'user@example.com',
  ]);
  registry.addCase(iamUserTestCase);
}

function addAutoScalingMatchTestCases(registry: RegexRegistry) {
  const autoScalingGroupNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):autoscaling:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:autoScalingGroup:(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}):autoScalingGroupName/(.{1,255})$`,
    'EC2 AutoScaling Group ARN, capture name',
    [
      'arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:00000000-0000-0000-0000-000000000000:autoScalingGroupName/my-group',
    ],
    [
      'arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:00000000-0000-0000-0000-000000000000:autoScalingGroupName/',
    ],
  );
  autoScalingGroupNameTestCase.addMatchTestCase(
    'arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:00000000-0000-0000-0000-000000000000:autoScalingGroupName/my-group',
    ['my-group'],
  );
  registry.addCase(autoScalingGroupNameTestCase);
}

function addCloudTrailMatchTestCases(registry: RegexRegistry) {
  const cloudTrailNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:trail/([A-Za-z0-9._-]{3,128})$`,
    'CloudTrail ARN, capture name',
    [],
    [],
  );
  registry.addCase(cloudTrailNameTestCase);
}

function addCodeBuildMatchTestCases(registry: RegexRegistry) {
  const codeBuildProjectNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):codebuild:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:project/([A-Za-z0-9][A-Za-z0-9\-_]{1,254})$`,
    'CodeBuild Project ARN, capture project name',
    [],
    [],
  );
  registry.addCase(codeBuildProjectNameTestCase);
}

function addEc2MatchTestCases(registry: RegexRegistry) {
  const securityGroupIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group/(sg-[0-9a-f]*)$`,
    'Security Group ARN, capture group ID',
    [],
    [],
  );
  registry.addCase(securityGroupIdTestCase);

  // TODO no need for two
  const securityGroupIdTestCaseAlternative: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group/(sg-[a-f0-9]{8,17})$`,
    'Security Group ARN, capture group ID',
    [],
    [],
  );
  registry.addCase(securityGroupIdTestCaseAlternative);

  // TODO no need for three
  const securityGroupIdTestCaseAlternativeTwo: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]):[0-9]{12}:security-group/(sg-[a-f0-9]{8,17})$`,
    'Security Group ARN, capture group ID',
    [],
    [],
  );
  registry.addCase(securityGroupIdTestCaseAlternativeTwo);

  const securityGroupIdTestCaseAlternativeThree: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^sg-[a-z0-9\-]+$`,
    'Security Group ID',
    ['sg-02ce123456e7893c'],
    ['sg-NOTREAL'],
  );
  registry.addCase(securityGroupIdTestCaseAlternativeThree);

  const vpcIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:.*:\d{12}:vpc/(vpc-[0-9a-f]{8,17})$`,
    'VPC ARN, capture VPC ID',
    [],
    [],
  );
  registry.addCase(vpcIdTestCase);

  // TODO no need for two
  const vpcIdTestCaseAlternative: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:.*:\d{12}:vpc/(vpc-[0-9a-f]{8,17}$)`,
    'VPC ARN, capture VPC ID',
    [],
    [],
  );
  registry.addCase(vpcIdTestCaseAlternative);

  const subnetIDTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:subnet\/(subnet-[0-9a-f]*)$`,
    'Subnet ARN',
    ['arn:aws:ec2:us-east-1:111111111111:subnet/subnet-017e22c0195eb5ded'],
    ['arn:aws:ec2:us-east-1:111111111111:subnet-017e22c0195eb5ded'],
  );
  registry.addCase(subnetIDTestCase);
}

function addLambdaMatchTestCases(registry: RegexRegistry) {
  const lambdaFunctionNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-us-gov|aws-cn):lambda:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:function:([a-zA-Z0-9\-_]{1,64})$`,
    'Lambda Function ARN, capture function name',
    [],
    [],
  );
  registry.addCase(lambdaFunctionNameTestCase);
}

function addRdsMatchTestCases(registry: RegexRegistry) {
  const manualSnapshotNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(cluster-snapshot|snapshot):([a-zA-Z][0-9a-zA-Z]*(?:-[0-9a-zA-Z]+)*)$`,
    'RDS manual Snapshot ARN, capture snapshot name',
    ['arn:aws:rds:us-east-1:111111111111:snapshot:blah', 'arn:aws:rds:us-east-1:111111111111:cluster-snapshot:blah'],
    [
      'arn:aws:rds:us-east-1:111111111111:snapshot:0startingNumber',
      'arn:aws:rds:us-east-1:111111111111:snapshot:-startingDash',
      'arn:aws:rds:us-east-1:111111111111:snapshot:endingDash-',
    ],
  );
  registry.addCase(manualSnapshotNameTestCase);

  const dbNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:db:((?!.*--.*)(?!.*-$)[a-z][a-z0-9-]{0,62})$`,
    'RDS DB ARN, capture DB name',
    [],
    [],
  );
  registry.addCase(dbNameTestCase);

  const snapshotNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:((?:cluster-)?snapshot|dbclustersnapshot):((?:rds:|awsbackup:)?((?!.*--.*)(?!.*-$)[a-zA-Z][a-zA-Z0-9-]{0,254}))$`,
    'RDS Snapshot ARN, capture snapshot, snapshot name with prefix, snapshot name without prefix',
    [],
    [],
  );
  registry.addCase(snapshotNameTestCase);
}

function addS3MatchTestCases(registry: RegexRegistry) {
  const bucketNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([a-z0-9.-]{3,63})$`,
    'S3 Bucket ARN, capture bucket name',
    [],
    [],
  );
  registry.addCase(bucketNameTestCase);

  // TODO no need for two
  const bucketNameTestCaseAlternative: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
    'S3 Bucket ARN, capture bucket name',
    [],
    [],
  );
  registry.addCase(bucketNameTestCaseAlternative);
}

function addKmsMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:key/([A-Za-z0-9-]{36})$`,
    'KMS Key ID, capture ID',
    [],
    [],
  );
  registry.addCase(keyIdTestCase);
}

function addRedshiftMatchTestCases(registry: RegexRegistry) {
  const clusterNameTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):redshift:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:cluster:(?!.*--)([a-z][a-z0-9-]{0,62})(?<!-)$`,
    'Redshift Cluster Name, capture name',
    [
      'arn:aws:redshift:us-east-1:111111111111:cluster:my-redshift-cluster-6',
      'arn:aws-us-gov:redshift:ap-northeast-1:111111111111:cluster:a',
    ],
    [
      'art:aws-cn:eu-north-1:111111111111:cluster:valid-3',
      'arn:aws-fictional:me-south-1:111111111111:cluster:a6-valid',
      'arn:aws:ca-central-1:111111111111:snapshot:snapshot-25',
      'arn:aws:af-south-1:111111111111:cluster:1-invalid',
      'arn:aws:us-west-2:111111111111:cluster:-also-invalid-6',
      'arn:aws:us-west-2:111111111111:cluster:still--invalid',
      'arn:aws:us-west-2:111111111111:cluster:again-invalid-6-',
      'arn:aws:us-west-2:111111111111:cluster:too-long-cluster-name-too-long-too-long-cluster-name-too-long-23',
    ],
  );
  clusterNameTestCase.addMatchTestCase('arn:aws-cn:redshift:ap-northeast-1:111111111111:cluster:my-cluster-25', [
    'my-cluster-25',
  ]);
  registry.addCase(clusterNameTestCase);
}

function addSQSMatchTestCases(registry: RegexRegistry) {
  const sqsQueueNameTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-us-gov|aws-cn):sqs:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:([a-zA-Z0-9_-]{1,80}(?:\.fifo)?)$`,
    'SQS Queue ARN, capture name',
    ['arn:aws:sqs:us-east-1:111111111111:valid_queue'],
    ['arn:aws-us-gov:sqs:us-gov-west-1:111111111111:invalid-queue.fifa'],
  );
  sqsQueueNameTestCase.addMatchTestCase('arn:aws:sqs:us-east-1:111111111111:valid_queue', ['valid_queue']);
  registry.addCase(sqsQueueNameTestCase);
}

function addSNSMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-us-gov|aws-cn):sns:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:([a-zA-Z0-9_-]{1,80}(?:\.fifo)?)$`,
    'SNS Topic ARN',
    ['arn:aws:sns:us-east-1:111111111111:TestTopic', 'arn:aws:sns:us-east-1:111111111111:TestTopic.fifo'],
    ['arn:aws:sns:us-east-1:111111111111:TestTopic.fifa'],
  );
  registry.addCase(keyIdTestCase);
}

function addEC2InstanceMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:instance\/(i-[0-9a-f]*)$`,
    'EC2 Instance ARN',
    ['arn:aws:ec2:us-east-1:111111111111:instance/i-077c4d5f32561ac45'],
    ['arn:aws:ec2:us-east-1:111111111111:instance/instance-notReal'],
  );
  registry.addCase(keyIdTestCase);
}

function addEC2InstanceIdMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^i-[a-f0-9]{8}(?:[a-f0-9]{9})?$`,
    'EC2 Instance Id',
    ['i-077c4d5f32561ac45'],
    ['instance-notReal'],
  );
  registry.addCase(keyIdTestCase);
}

function addECRRepositoryARNMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ecr:[a-z]{2}-[a-z]+-\d{1}:\d{12}:repository\/([a-z0-9._\/\-]+)$`,
    'ECR Repository ARN',
    ['arn:aws:ecr:us-east-1:111111111111:repository/test'],
    ['arn:aws:ecr:us-east-1:111111111111:fakerepository/NOTREAL'],
  );
  registry.addCase(keyIdTestCase);
}

function addECRRepositoryMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`([a-z0-9._\/\-]+)$`,
    'ECR Repository Name',
    ['test-repository'],
    ['NOTREAL'],
  );
  registry.addCase(keyIdTestCase);
}

function addCloudFrontMatchTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^(arn:(?:aws|aws-us-gov|aws-cn):cloudfront::\d{12}:distribution\/([A-Z0-9]+))$`,
    'CloudFront Distribution ARN',
    ['arn:aws:cloudfront::111111111111:distribution/D531CA4V1232D8'],
    ['arn:aws:cloudfront::111111111111:fakedistribution/NOTREAL'],
  );
  registry.addCase(keyIdTestCase);
}

function addCloudFrontMatchTestCasesAlternative(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):cloudfront::[0-9]{12}:distribution\/([A-Z0-9]*)$`,
    'CloudFront Distribution ARN',
    ['arn:aws:cloudfront::111111111111:distribution/EDFDVB6EXAMPLE'],
    ['arn:aws:cloudfront::111111111111:fakedistribution/NOTREAL'],
  );
  registry.addCase(keyIdTestCase);
}

function addCloudFrontDistributionIdTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^[A-Za-z0-9]*$`,
    'CloudFront Distribution ID',
    ['EDFDVB6EXAMPLE'],
    ['NOT-REAL'],
  );
  registry.addCase(keyIdTestCase);
}

function addCloudFrontDefaultObjectTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^[\w._-~]{1,255}$`,
    'DefaultRootObject',
    ['index.html'],
    [],
  );
  registry.addCase(keyIdTestCase);
}

function addSSMDocumentArnTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^(arn:(?:aws|aws-cn|aws-us-gov):ssm:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:document\/[A-Za-z0-9][A-Za-z0-9\-_]{1,254})$`,
    'SSM Document ARN',
    ['arn:aws:ssm:us-east-1:111111111111:document/test'],
    ['arn:aws:ssm:us-east-1:111111111111:notDocument/test'],
  );
  registry.addCase(keyIdTestCase);
}

function addTransitGatewayIdTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^tgw-[a-z0-9\-]+$`,
    'Transit Gateway ID',
    ['tgw-0111d111d1d1a111b'],
    ['tgw-NOTATRANSITGATEWAY'],
  );
  registry.addCase(keyIdTestCase);
}

function addTransitGatewayARNTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:[a-z]{2}-[a-z]+-\d{1}:\d{12}:transit-gateway\/(tgw-[a-z0-9\-]+)$`,
    'Transit Gateway ARN',
    ['arn:aws:ec2:us-east-1:111111111111:transit-gateway/tgw-0111d111d1d1a111b'],
    ['arn:aws:ec2:us-east-1:111111111111:not-transit-gateway/tgw-0111d111d1d1a111b'],
  );
  registry.addCase(keyIdTestCase);
}

function addSecretsManagerArnTestCases(registry: RegexRegistry) {
  const keyIdTestCase: RegexMatchTestCase = new RegexMatchTestCase(
    String.raw`^arn:(?:aws|aws-cn|aws-us-gov):secretsmanager:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:secret:([A-Za-z0-9\/_+=.@-]+)$`,
    'Secrets Manager Secret ARN',
    ['arn:aws:secretsmanager:us-east-1:111111111111:secret:test'],
    ['arn:aws:secretsmanager:us-east-1:111111111111:not-secret:test'],
  );
  registry.addCase(keyIdTestCase);
}

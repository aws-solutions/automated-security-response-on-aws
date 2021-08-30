import { SynthUtils } from '@aws-cdk/assert';
import '@aws-cdk/assert/jest';
import { App, Stack } from '@aws-cdk/core';
import { OrchestratorConstruct } from '../Orchestrator/lib/common-orchestrator-construct';
import * as kms from '@aws-cdk/aws-kms';
import { StringParameter } from '@aws-cdk/aws-ssm';
import { 
    PolicyStatement, 
    PolicyDocument, 
    ServicePrincipal,
    AccountRootPrincipal,
} from '@aws-cdk/aws-iam';

test('test App Orchestrator Construct', () => {

    const app = new App();
    const stack = new Stack(app, 'testStack', {
        stackName: 'testStack'
    });

    const kmsKeyPolicy:PolicyDocument = new PolicyDocument()
    
    const kmsServicePolicy = new PolicyStatement({
        principals: [
            new ServicePrincipal('sns.amazonaws.com'),
            new ServicePrincipal(`logs.${stack.urlSuffix}`)
        ],
        actions: [
            "kms:Encrypt*",
            "kms:Decrypt*",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:Describe*"
        ],
        resources: [
            '*'
        ]
    })
    kmsKeyPolicy.addStatements(kmsServicePolicy)

    const kmsRootPolicy = new PolicyStatement({
        principals: [
            new AccountRootPrincipal()
        ],
        actions: [
            'kms:*'
        ],
        resources: [
            '*'
        ]
    })
    kmsKeyPolicy.addStatements(kmsRootPolicy)

    const kmsKey = new kms.Key(stack, 'SHARR-key', {
        enableKeyRotation: true,
        alias: 'TO0111-SHARR-Key',
        trustAccountIdentities: true,
        policy: kmsKeyPolicy
    });

    const kmsKeyParm = new StringParameter(stack, 'SHARR_Key', {
        description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
        parameterName: `/Solutions/SO0111/CMK_ARN`,
        stringValue: kmsKey.keyArn
    });

    new OrchestratorConstruct(stack, 'Orchestrator', {
	    roleArn: 'arn:aws-test:iam::111111111111:role/TestRole',
	    ssmDocStateLambda: 'xxx',
	    ssmExecDocLambda: 'yyy',
	    ssmExecMonitorLambda: 'zzz',
	    notifyLambda: 'aaa',
        solutionId: 'bbb',
        solutionName: 'This is a test',
        solutionVersion: '1.1.1',
        orchLogGroup: 'ORCH_LOG_GROUP',
        kmsKeyParm: kmsKeyParm
    });

    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});
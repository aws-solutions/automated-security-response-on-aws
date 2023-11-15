import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as codepipeline from 'aws-cdk-lib/aws-codepipeline';
import * as codepipeline_actions from 'aws-cdk-lib/aws-codepipeline-actions';
import * as iam from 'aws-cdk-lib/aws-iam';
import { StackSetAutomationConfig } from './stackset-interface';

/*
  Bootstrap properties
*/
interface StackSetAutomationProps extends cdk.StackProps{
    stackSetConfig: StackSetAutomationConfig
    Bucket: s3.Bucket
    BucketIdName: string
}

export class StackSetAutomation extends cdk.Stack {

    targetAccounts: Map<string, string> = new Map<string, string>()
    prefix: string

    constructor(scope: cdk.App, id: string, props: StackSetAutomationProps) {
        super(scope, id, props);

        this.targetAccounts = props.stackSetConfig.TargetAccounts || new Map<string, string>();
        this.targetAccounts.set("Audit", process.env.CDK_DEFAULT_ACCOUNT as string);

        this.prefix = `${props.stackSetConfig.StackSetId}-Audit`;
        const stackSetName = props.stackSetConfig.StackSetName

        // S3 Artifact for CodePipeline
        const artifactBucket = new s3.Bucket(this, `CodePipelineArtifacts-${this.prefix}`, {
            removalPolicy: cdk.RemovalPolicy.DESTROY, 
            bucketName: `secops-asr-${props.BucketIdName.toLowerCase()}-cp-${props.stackSetConfig.StackSetId.toLowerCase().slice(0,14)}`,
            versioned: true,
            blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL
        });

        // // IAM Role for CodeBuild
        const stagesRole = new iam.Role(this, `StagesRole-${this.prefix}`, {
            assumedBy: new iam.ServicePrincipal('codepipeline.amazonaws.com')
        });

        props.Bucket.grantReadWrite(stagesRole);

        const sourceOutput = new codepipeline.Artifact('SourceOutput');

        // // CodePipeline
        const pipeline = new codepipeline.Pipeline(this,`CodePipeline-${this.prefix}`,{
                crossAccountKeys: false,
                role: stagesRole,
                artifactBucket: artifactBucket
            }
        );
        
        // // Add stage for the source from S3Bucket
        pipeline.addStage({
            stageName: 'Source',
            actions: [
                new codepipeline_actions.S3SourceAction({
                    actionName: 'SourceAction',
                    bucket: props.Bucket,
                    bucketKey: `${props.stackSetConfig.BucketKey}/${props.stackSetConfig.TemplateName}.zip`,
                    output: sourceOutput,
                    role: stagesRole
                }),
            ]
        });
        
        // // Iterates the target accounts to create a stage for the CodePipeline
        for (const [accountName, accountNumber] of this.targetAccounts.entries()) {
            
            const buildOutput = new codepipeline.Artifact(`BuildOutput${accountName}`);
            this.prefix = `${props.stackSetConfig.StackSetId}-${accountName}`;

            // IAM Role for CodeBuild
            const codeBuildRole = new iam.Role(this, `CodeBuildRole-${this.prefix}`, {
                assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com')
            });

            // Configure the CodeBuildProject to use the CodeBuild Role
            codeBuildRole.addToPolicy(
                new iam.PolicyStatement({
                    actions: ['cloudformation:UpdateStackSet'],
                    resources: [`arn:aws:cloudformation:${this.region}:${accountNumber}:stackset/*`],
                })
            );

            codeBuildRole.addToPolicy(
                new iam.PolicyStatement({
                    actions: ['s3:GetObject'], 
                    resources: [`arn:aws:s3:::${props.Bucket.bucketName}/*`],
                })
            );
            
            // Grant permissions on the artifact  
            artifactBucket.grantReadWrite(codeBuildRole);        

            const updateStackSetcommand = [``];
    
            // If the account is different than the current context
            if(accountNumber != process.env.CDK_DEFAULT_ACCOUNT as string){
                codeBuildRole.addToPolicy(
                    new iam.PolicyStatement({
                        actions: ['sts:AssumeRole'], 
                        resources: [`arn:aws:iam::${accountNumber}:role/AWSCloudFormationStackSetExecutionRole`],
                    })
                );
                // Assume the ASR Role for the target account
                updateStackSetcommand.push(`aws sts assume-role --role-arn arn:aws:iam::${accountNumber}:role/AWSCloudFormationStackSetExecutionRole --role-session-name tempPayerSession --output json > assumed-role.json`);
                updateStackSetcommand.push(`export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId assumed-role.json)`);
                updateStackSetcommand.push(`export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey assumed-role.json)`);
                updateStackSetcommand.push(`export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken assumed-role.json)`);
            }
            
            // Update the StackSet
            updateStackSetcommand.push('rs=$(aws cloudformation update-stack-set --stack-set-name ' + stackSetName + ' \\');
            // https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStackSet.html
            if (props.stackSetConfig.TemplateFromS3) {
                // maximum size: 51,200 bytes
                updateStackSetcommand.push(`--template-url https://${props.Bucket.bucketName}.s3.${this.region}.amazonaws.com/aws-security-hub-automated-response-and-remediation/v2.0.2/${props.stackSetConfig.TemplateName}.template \\`);
            } else {
                // maximum size: 460,800 bytes
                updateStackSetcommand.push(`--template-body file://${props.stackSetConfig.TemplateName}.template \\`);
            }

            // StackeSet parameters
            updateStackSetcommand.push(
                `--parameters ${props.stackSetConfig.StackSetParameters.join(' ')} \\`,
                '--operation-preferences FailureToleranceCount=10,MaxConcurrentCount=40,RegionConcurrencyType=PARALLEL \\',
                `--description "${props.stackSetConfig.TemplateDescription}" \\`,
                '--capabilities CAPABILITY_NAMED_IAM \\',
                ')'
            );

            // CodeBuild project
            const codeBuildProject = new codebuild.PipelineProject(this, `CodeBuildProject-${this.prefix}`, {
                // Environment definition
                environment: {
                    buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
                    computeType: codebuild.ComputeType.SMALL
                },
                // Buildspec
                buildSpec: codebuild.BuildSpec.fromObject({
                    version: '0.2',
                    phases: {
                        build: {
                            commands: [
                                updateStackSetcommand.join("\n")
                            ],
                        },
                    },
                    artifacts: {
                        files: '**/*',
                    }
                }),
                role: codeBuildRole
            });

            // Added build for the target account
            pipeline.addStage({
                stageName: `BuildTo${accountName}`,
                actions: [
                    new codepipeline_actions.CodeBuildAction({
                        actionName: 'BuildAction',
                        input: sourceOutput,
                        outputs: [buildOutput],
                        project: codeBuildProject
                    }),
                ],
            });

        };
        
    }
    
}
function getS3BucketName(bucketName: string) {
    const cleanedBaseName = bucketName
        .toLowerCase() 
        .replace(/[^a-z0-9]/g, '');
    const truncatedName = cleanedBaseName.slice(0, 63);
    return truncatedName;
}
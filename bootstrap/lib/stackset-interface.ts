export interface StackSetAutomationConfig {
    BucketKey: string;
    StackSetId: string;
    StackSetName: string;
    StackSetParameters: any;
    TemplateName: string;
    TemplateDescription: string;
    TemplateFromS3: boolean;
    TargetAccounts: Map<string, string>;
}
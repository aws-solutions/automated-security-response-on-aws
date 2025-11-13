# API Lambda Functions

Each Lambda function backing ASR's API is using this code bundle. Each individual lambda function has a separate entry
point in the /handlers directory.

## Structure

```
├── clients/                    # Client classes to communicate with external systems, e.g. S3
│   └── s3.ts
├── handlers/                   # Entry points for the different Lambda functiuns that use this code bundle
│   ├── findings.ts             # handler for all /findings API endpoints
│   └── deployWebui.ts          # CustomResource to deploy the WebUI
├── models/                     # Data models. Need to be in sync with the corresponding models in the webio.
│   └── finding.ts
```

# Recording AI-generated remediation provenance

ASR records whether a built-in remediation was AI-generated. This metadata is
part of the source contribution and must match the registered remediation
identifier.

## Built-in remediations

Add the identifier to `AI_GENERATED_REMEDIATION_IDS` in
`source/layer/metrics.py`:

```python
AI_GENERATED_REMEDIATION_IDS: frozenset[str] = frozenset(
    {
        "S3.14",
    }
)
```

The value must match the `control` entry in the relevant
`source/playbooks/*/lib/*_remediations.ts` file exactly. Add one entry for each
AI-generated remediation and preserve existing entries.

Also add the repository provenance marker to each generated artifact:

| Artifact | Marker |
|---|---|
| remediation runbook YAML | `AIGenerated: "true"` in the description |
| control runbook TypeScript | `// AIGenerated: true` |
| description Markdown | `AIGenerated: "true"` |
| generated Python handler | `# AIGenerated: true` |

The source marker documents authorship. The `metrics.py` entry supplies the
runtime telemetry value; one does not replace the other.

## Runtime Custom Runbooks

A Custom Runbook created in a deployed environment cannot modify the solution's
packaged `metrics.py` set. Keep the provenance marker in the runbook description,
but do not claim that the deployed solution reports it as AI-generated unless the
identifier is already present in the packaged set.

## Completion check

1. The built-in remediation identifier is present in
   `AI_GENERATED_REMEDIATION_IDS`.
2. It exactly matches the registered `control` value.
3. Every generated artifact carries the appropriate provenance marker.
4. Existing identifiers remain unchanged.

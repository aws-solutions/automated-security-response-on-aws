# Recording AI-generated remediation provenance

ASR records whether a remediation was AI-generated, for both built-in
remediations and runtime Custom Runbooks. Each path records it differently.

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
packaged `metrics.py` set. Instead, put `AIGenerated: "true"` on its own line in
the runbook's top-level `description`, after the last section. ASR records the
marker when the runbook is registered and reports the remediations that version
runs, queues, or fails as AI-generated. A version registered without the marker
reports `false`; register a new version to change it. An execution that Step
Functions times out or aborts is reported without the flag.

## Completion check

1. A built-in remediation identifier is present in
   `AI_GENERATED_REMEDIATION_IDS`, and exactly matches the registered `control`
   value.
2. A Custom Runbook's top-level `description` carries `AIGenerated: "true"` on
   its own line.
3. Every generated artifact carries the appropriate provenance marker.
4. Existing identifiers remain unchanged.

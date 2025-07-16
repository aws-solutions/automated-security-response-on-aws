# Security Controls Playbook

The Security Controls (SC) playbook creates the necessary AWS resources for remediating the controls listed in `SC/lib/sc_remediations.ts`.

This playbook consolidates all remediations from all playbooks in ASR, and supports the use of "Consolidated Control Findings" in Security Hub.
See the [Automated Security Response on AWS Implementation Guide](https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/welcome.html) for more information on this Playbook.

See [How consolidation impacts control IDs and titles](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-changes-consolidation.html#securityhub-findings-format-changes-ids-titles) for more information on consolidated control findings in [AWS Security Hub](https://aws.amazon.com/security-hub)

	 
# NEWPLAYBOOK v1.0.0 Playbook

The NEWPLAYBOOK (NEWPB) playbook is part of the AWS Security Hub Automated Response and Remediation solution. It is an example and starting point for creating a custom automated remdiation playbook.

* Example.1
* Example.2
  
Note that in the example remediation, ssmdocs/AFSBP_RDS.6.yaml, the line:
```
%%SCRIPT=common/parse_input.py%%
```
...loads parse_input.py from playbooks/common. This same parse code is used in all the the current playbooks.

See the README.md in the root of this archive and the [AWS Security Hub Automated Response and Remediation Implementation Guide](https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/welcome.html) for more information.

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_policy_allowing_confused_services,
)
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_key_confused_service(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            if (
                key.manager == "CUSTOMER" and key.state == "Enabled"
            ):  # only customer KMS have policies
                report = Check_Report_AWS(self.metadata())
                report.status = "PASS"
                report.status_extended = (
                    f"KMS key {key.id} is not exposed via confused deputy services."
                )
                report.resource_id = key.id
                report.resource_arn = key.arn
                report.resource_tags = key.tags
                report.region = key.region
                # If the "Principal" element value is set to { "AWS": "*" } and the policy statement is not using any Condition clauses to filter the access, the selected AWS KMS master key is publicly accessible.
                if is_policy_allowing_confused_services(
                    key.policy,
                    kms_client.audited_account,
                ):
                    report.status = "FAIL"
                    report.status_extended = f"KMS key {key.id} may be accessed via confused deputy services."
                findings.append(report)
        return findings

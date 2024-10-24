from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_policy_allowing_confused_services,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_public_service(Check):
    def execute(self):
        findings = []
        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags
            report.status = "PASS"
            report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy but it does not over-trust AWS services."

            if not bucket.policy:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have a bucket policy."
                )
            elif is_policy_allowing_confused_services(
                bucket.policy, s3_client.audited_account, is_cross_account_allowed=True
            ):
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy allowing AWS service access without source Conditions."

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_policy_allowing_confused_services,
)
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_confused_service(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(self.metadata())
            report.region = topic.region
            report.resource_id = topic.name
            report.resource_arn = topic.arn
            report.resource_tags = topic.tags
            report.status = "PASS"
            report.status_extended = (
                f"SNS topic {topic.name} blocks confused deputy attacks."
            )
            if topic.policy and is_policy_allowing_confused_services(topic.policy):
                report.status = "FAIL"
                report.status_extended = (
                    f"SNS topic {topic.name} allows confused deputy attacks."
                )

            findings.append(report)

        return findings

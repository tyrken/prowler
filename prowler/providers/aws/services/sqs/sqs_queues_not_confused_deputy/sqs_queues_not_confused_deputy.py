from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_policy_allowing_confused_services,
)
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


class sqs_queues_not_confused_deputy(Check):
    def execute(self):
        findings = []
        for queue in sqs_client.queues:
            report = Check_Report_AWS(self.metadata())
            report.region = queue.region
            report.resource_id = queue.id
            report.resource_arn = queue.arn
            report.resource_tags = queue.tags
            report.status = "PASS"
            report.status_extended = f"SQS queue {queue.id} is not public."
            if queue.policy:
                if is_policy_allowing_confused_services(queue.policy):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"SQS queue {queue.id} is subject to confused deputy attacks."
                    )

            findings.append(report)

        return findings

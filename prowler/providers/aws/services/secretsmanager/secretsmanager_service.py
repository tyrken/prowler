import json
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class SecretsManager(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.secrets = {}
        self.__threading_call__(self._list_secrets)
        self.__threading_call__(self._get_resource_policy, self.secrets.values())

    def _list_secrets(self, regional_client):
        logger.info("SecretsManager - Listing Secrets...")
        try:
            list_secrets_paginator = regional_client.get_paginator("list_secrets")
            for page in list_secrets_paginator.paginate():
                for secret in page["SecretList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(secret["ARN"], self.audit_resources)
                    ):
                        # We must use the Secret ARN as the dict key to have unique keys
                        self.secrets[secret["ARN"]] = Secret(
                            arn=secret["ARN"],
                            name=secret["Name"],
                            region=regional_client.region,
                            last_accessed_date=secret.get(
                                "LastAccessedDate", datetime.min
                            ).replace(tzinfo=timezone.utc),
                            tags=secret.get("Tags"),
                        )
                        if "RotationEnabled" in secret:
                            self.secrets[secret["ARN"]].rotation_enabled = secret[
                                "RotationEnabled"
                            ]

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _get_resource_policy(self, secret):
        logger.info("SecretsManager - Getting Resource Policy...")
        try:
            secret_policy = self.regional_clients[secret.region].get_resource_policy(
                SecretId=secret.arn
            )
            if secret_policy.get("ResourcePolicy"):
                secret.policy = json.loads(secret_policy["ResourcePolicy"])
        except Exception as error:
            logger.error(
                f"{self.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class Secret(BaseModel):
    arn: str
    name: str
    region: str
    policy: Optional[dict] = None
    rotation_enabled: bool = False
    last_accessed_date: datetime
    tags: Optional[list] = []

# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import re

from pydantic import ConfigDict
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import SUCCESS_MESSAGE
from ..helper import query_url

logger = getLogger()


class UrlReputationParams(Params):
    url: str = Param(
        description="URL to query for Phishing information",
        primary=True,
        cef_types=["url"],
        required=True,
    )


class UrlReputationOutput(ActionOutput):
    # Legacy actions returned the complete API result, including undeclared fields.
    model_config = ConfigDict(extra="allow")

    url: str | None = OutputField(
        column_name="URL",
        cef_types=["url"],
        example_values=["http://www.testurl.com"],
    )
    valid: bool | None = OutputField(column_name="Valid", example_values=[False, True])
    phish_id: str | None = OutputField(column_name="Phish ID", example_values=["62771"])
    in_database: bool = OutputField(
        column_name="In Database", example_values=[False, True]
    )
    verified: bool | None = OutputField(
        column_name="Verified", example_values=[False, True]
    )
    phish_detail_page: str | None = OutputField(
        column_name="Detail URL",
        cef_types=["url"],
        example_values=["http://www.exampleurl.com/test_detail.php?phish_id=62001"],
    )
    verified_at: str | None = OutputField(example_values=["2006-09-01T02:32:23+00:00"])


class UrlReputationSummary(ActionOutput):
    in_database: bool = OutputField(alias="In_Database", example_values=[False, True])
    valid: bool | None = OutputField(alias="Valid", example_values=[False, True])
    verified: bool | None = OutputField(alias="Verified", example_values=[False, True])


@app.action(
    name="url reputation",
    identifier="check_url",
    description="Queries PhishTank for URL's phishing reputation",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=UrlReputationSummary,
    verbose="If URL information is unavailable in PhishTank, only 'url' and 'in_database' property would be populated.",
)
def check_url(
    params: UrlReputationParams, soar: SOARClient, asset: Asset
) -> UrlReputationOutput:
    normalized_url = re.sub(
        r"^hxxp(s?)://",
        lambda match: f"http{match.group(1).lower()}://",
        params.url,
        flags=re.IGNORECASE,
    )
    normalized_url = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", normalized_url)
    logger.info("Querying URL: %s", normalized_url)
    result = query_url(asset, normalized_url)
    # PhishTank can return an integer ID; the original manifest declares a string.
    if result.get("phish_id") is not None:
        result = {**result, "phish_id": str(result["phish_id"])}
    output = UrlReputationOutput(**result)
    soar.set_summary(
        UrlReputationSummary(
            in_database=output.in_database, valid=output.valid, verified=output.verified
        )
    )
    soar.set_message(SUCCESS_MESSAGE)
    return output

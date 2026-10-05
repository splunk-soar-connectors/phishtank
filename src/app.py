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
import time

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

from .consts import DEFAULT_USER_AGENT
from .helper import check_connectivity

logger = getLogger()


class Asset(BaseAsset):
    apikey: str | None = AssetField(
        default=None,
        description="API key",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    user_agent: str = AssetField(
        required=False,
        default=DEFAULT_USER_AGENT,
        description="User-Agent header to pass in the request (Default: splunk_soar_user)",
        category=FieldCategory.CONNECTIVITY,
    )


app = App(
    name="PhishTank",
    app_type="investigative",
    logo="logo_phishtank.svg",
    logo_dark="logo_phishtank_dark.svg",
    product_vendor="OpenDNS",
    product_name="PhishTank",
    publisher="Splunk",
    appid="c193026d-46cf-4f17-b4b9-f22525d2d87e",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validates the connectivity by querying PhishTank."""
    logger.info("Polling Phishtank site ...")
    time.sleep(10)
    check_connectivity(asset)
    soar.set_message("Connectivity test passed")


from .actions import check_url  # noqa: F401

if __name__ == "__main__":
    app.cli()

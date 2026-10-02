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
from typing import TYPE_CHECKING

from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import API_URL, DEFAULT_TIMEOUT, INVALID_RESPONSE_MESSAGE

if TYPE_CHECKING:
    from .app import Asset

logger = getLogger()


def make_request(asset: "Asset", url: str):
    import requests  # noqa: PLC0415

    data = {"url": url, "format": "json"}
    if asset.apikey:
        data["app_key"] = asset.apikey
    try:
        return requests.post(
            API_URL,
            data=data,
            headers={"User-Agent": f"phishtank/{asset.user_agent}"},
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ActionFailure(f"Server connection error: {exc}") from exc


def check_connectivity(asset: "Asset") -> None:
    response = make_request(asset, "https://www.google.com")
    if not 200 <= response.status_code < 399:
        raise ActionFailure(
            f"Connectivity test failed. Server returned error code: {response.status_code}. Please check your network connectivity"
        )


def query_url(asset: "Asset", url: str) -> dict:
    response = make_request(asset, url)
    logger.debug("PhishTank response status: %s", response.status_code)
    if response.status_code in (509, 429):
        raise ActionFailure(
            f"Query is being rate limited. Server returned {response.status_code}"
        )
    if not 200 <= response.status_code < 399:
        raise ActionFailure(f"Server returned error code: {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ActionFailure(f"Error parsing PhishTank response: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        raise ActionFailure(INVALID_RESPONSE_MESSAGE)
    result = payload["results"]
    if not isinstance(result.get("in_database"), bool):
        raise ActionFailure(INVALID_RESPONSE_MESSAGE)
    if result["in_database"] and any(
        key not in result for key in ("verified", "valid")
    ):
        raise ActionFailure(
            "Error populating summary: response is missing verified or valid"
        )
    return result

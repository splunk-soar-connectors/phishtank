# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generic HTTP request action for the PhishTank API."""

import json
from typing import Any

import requests
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app
from ..consts import API_BASE_URL, DEFAULT_TIMEOUT

logger = getLogger()


class PhishTankMakeRequestParams(MakeRequestParams):
    """Generic request parameters with PhishTank endpoint guidance."""

    endpoint: str = Param(
        description=(
            "PhishTank API endpoint path. For URL lookups, use 'checkurl/'. "
            "The endpoint is appended to https://checkurl.phishtank.com/."
        ),
        required=True,
    )


@app.make_request()
def make_request(params: PhishTankMakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Send a generic HTTP request to the configured PhishTank API host."""
    endpoint = params.endpoint.strip().lstrip("/")
    if not endpoint:
        raise ActionFailure("The endpoint parameter is required.")
    if endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            "Do not include the base URL in the endpoint. "
            "Provide only a PhishTank API path, such as 'checkurl/'."
        )

    url = f"{API_BASE_URL}{endpoint}"

    headers = {"User-Agent": f"phishtank/{asset.user_agent}"}
    if params.headers:
        try:
            extra_headers = json.loads(params.headers)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from exc
        if not isinstance(extra_headers, dict):
            raise ActionFailure("The headers parameter must be a JSON object.")
        headers.update(extra_headers)

    query_params: dict[str, Any] | None = None
    if params.query_parameters:
        try:
            parsed_query = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.lstrip("?")
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{query_string}"
        else:
            if not isinstance(parsed_query, dict):
                raise ActionFailure(
                    "The query_parameters parameter must be a JSON object or query string."
                )
            query_params = parsed_query

    body = None
    if params.body:
        try:
            body = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ActionFailure(f"Invalid JSON body: {params.body}") from exc

    request_body: dict[str, Any] | None = None
    form_body = endpoint.rstrip("/") == "checkurl"
    if form_body:
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise ActionFailure("The checkurl endpoint requires a JSON object body.")
        request_body = body
        if asset.apikey:
            request_body.setdefault("app_key", asset.apikey)

    try:
        request_kwargs: dict[str, Any] = {
            "method": params.http_method,
            "url": url,
            "headers": headers,
            "params": query_params,
            "verify": params.verify_ssl if params.verify_ssl is not None else True,
        }
        if form_body:
            request_kwargs["data"] = request_body
        else:
            request_kwargs["json"] = body
        response = requests.request(
            **request_kwargs,
            timeout=params.timeout or DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.exception("PhishTank make request failed")
        raise ActionFailure(f"Request failed: {exc}") from exc

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )

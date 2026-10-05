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
from inspect import unwrap
from unittest.mock import Mock

import pytest
import requests
from soar_sdk.exceptions import ActionFailure

from src.actions.check_url import UrlReputationOutput, UrlReputationParams, check_url
from src.app import Asset
from src.app import test_connectivity as connectivity
from src.helper import query_url

# Exercise handler logic without the SDK's platform invocation wrapper.
check_url = unwrap(check_url)
connectivity = unwrap(connectivity)


@pytest.fixture
def response(monkeypatch):
    response = requests.Response()
    response.status_code = 200
    response.json = Mock(
        return_value={"results": {"url": "https://example.com", "in_database": False}}
    )
    monkeypatch.setattr(requests, "post", Mock(return_value=response))
    return response


def test_unknown_url(response):
    soar = Mock()
    output = check_url(UrlReputationParams(url="https://example.com"), soar, Asset())
    assert output.in_database is False
    assert output.valid is None
    assert output.verified is None
    assert output.phish_id is None
    summary = soar.set_summary.call_args.args[0].model_dump(by_alias=True)
    assert summary == {"In_Database": False, "Valid": None, "Verified": None}


def test_output_preserves_unexpected_declared_field_type():
    result = {
        "url": "https://example.com",
        "in_database": False,
        "valid": "unknown",
        "verified": None,
        "phish_id": None,
        "phish_detail_page": None,
        "verified_at": None,
    }
    output = UrlReputationOutput(**result)
    assert output.model_dump(by_alias=True) == result


def test_known_url(response):
    response.json.return_value = {
        "results": {
            "url": "https://example.com",
            "in_database": True,
            "valid": True,
            "verified": False,
            "phish_id": 62771,
            "phish_detail_page": "https://example.com/detail",
            "verified_at": None,
        }
    }
    output = check_url(UrlReputationParams(url="https://example.com"), Mock(), Asset())
    assert output.phish_id == 62771
    assert output.model_dump(by_alias=True)["phish_id"] == 62771
    assert output.valid is True
    assert output.verified is False


@pytest.mark.parametrize(
    "extra_fields",
    [
        {"submitted_at": "2006-10-01T02:28:46+00:00"},
        {"extra_details": {"source": "api", "count": 2}},
        {"extra_labels": ["reported", "verified"]},
    ],
)
def test_serialized_output_preserves_extra_api_fields(response, extra_fields):
    result = {
        "url": "https://example.com",
        "in_database": True,
        "valid": True,
        "verified": True,
        "phish_id": 62771,
        "phish_detail_page": "https://example.com/detail",
        "verified_at": "2006-10-01T02:28:46+00:00",
        **extra_fields,
    }
    response.json.return_value = {"results": result}
    output = check_url(UrlReputationParams(url=result["url"]), Mock(), Asset())
    # SOAR serializes action data with model_dump(by_alias=True).
    assert output.model_dump(by_alias=True) == result
    assert output.model_dump(mode="json", by_alias=True) == result


@pytest.mark.parametrize(
    "url", ["hxxps://example[.]com", "HXXPS://example(.)com", "https://example{.}com"]
)
def test_defanged_url_and_auth(response, url):
    check_url(
        UrlReputationParams(url=url),
        Mock(),
        Asset(apikey="test-key", user_agent="custom"),  # pragma: allowlist secret
    )
    kwargs = requests.post.call_args.kwargs
    assert kwargs["data"] == {
        "url": "https://example.com",
        "format": "json",
        "app_key": "test-key",
    }
    assert kwargs["headers"] == {"User-Agent": "phishtank/custom"}
    assert kwargs["timeout"] == 30


def test_optional_api_key(response):
    query_url(Asset(), "https://example.com")
    assert "app_key" not in requests.post.call_args.kwargs["data"]


@pytest.mark.parametrize("status", [429, 509])
def test_rate_limit(response, status):
    response.status_code = status
    with pytest.raises(ActionFailure, match="rate limited"):
        query_url(Asset(), "https://example.com")


@pytest.mark.parametrize(
    "payload",
    [[], {}, {"results": []}, {"results": {}}, {"results": {"in_database": "false"}}],
)
def test_invalid_response(response, payload):
    response.json.return_value = payload
    with pytest.raises(ActionFailure, match="expected response"):
        query_url(Asset(), "https://example.com")


def test_invalid_json(response):
    response.json.side_effect = ValueError("invalid JSON")
    with pytest.raises(ActionFailure, match="Error parsing"):
        query_url(Asset(), "https://example.com")


def test_http_error(response):
    response.status_code = 503
    with pytest.raises(ActionFailure, match="503"):
        query_url(Asset(), "https://example.com")


def test_connection_error(response):
    requests.post.side_effect = requests.Timeout("request timed out")
    with pytest.raises(ActionFailure, match="Server connection error"):
        query_url(Asset(), "https://example.com")


def test_connectivity_checks_status_without_json(response, monkeypatch):
    monkeypatch.setattr("time.sleep", Mock())
    soar = Mock()
    connectivity(soar, Asset())
    response.json.assert_not_called()
    soar.set_message.assert_called_once_with("Connectivity test passed")


def test_connectivity_failure(response, monkeypatch):
    monkeypatch.setattr("time.sleep", Mock())
    response.status_code = 403
    with pytest.raises(ActionFailure, match="Connectivity test failed"):
        connectivity(Mock(), Asset())

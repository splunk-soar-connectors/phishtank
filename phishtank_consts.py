# File: phishtank_consts.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
DEFAULT_TIMEOUT = 30

PHISHTANK_DOMAIN = "http://www.phishtank.com"
PHISHTANK_API_DOMAIN = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_APP_KEY = "app_key"
PHISHTANK_DEFAULT_USER = "splunk_soar_user"
PHISHTANK_MSG_QUERY_URL = "Querying URL: {query_url}"
PHISHTANK_MSG_CONNECTING = "Polling Phishtank site ..."
PHISHTANK_SERVICE_SUCC_MSG = "Phishtank Service successfully executed."
PHISHTANK_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
PHISHTANK_ERROR_CONNECTIVITY_TEST = "Connectivity test failed"
PHISHTANK_MSG_GOT_RESP = "Got response from Phishtank"
PHISHTANK_NO_RESPONSE = "Server did not return a response \
                         for the object queried"
PHISHTANK_SERVER_CONNECTION_ERROR = "Server connection error"
PHISHTANK_MSG_CHECK_CONNECTIVITY = "Please check your network connectivity"
PHISHTANK_SERVER_RETURNED_ERROR_CODE = "Server returned error code: {code}"
PHISHTANK_ERROR_MSG_OBJECT_QUERIED = "Phishtank response didn't \
                                    send expected response"
PHISHTANK_SERVER_ERROR_RATE_LIMIT = "Query is being rate limited. \
                                     Server returned {}"
PHISHTANK_ERROR_MSG = "Unknown error occurred. Please check the asset configuration and|or action parameters"

# File: phishtank_connector.py
#
# Copyright (c) 2016-2023 Splunk Inc.
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
# Phantom imports
import sys
import time

import phantom.app as phantom
import requests
# Global imports
import simplejson as json
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Local imports
import phishtank_consts


class PhishtankConnector(BaseConnector):
    ACTION_ID_WHOIS_DOMAIN = 'check_url'

    def __init__(self):
        self._api_key = None
        self._headers = None
        super(PhishtankConnector, self).__init__()

    def initialize(self):
        config = self.get_config()
        self._api_key = config.get('apikey', None)
        self._headers = {
            "User-Agent": f"{'phishtank/'}{config.get('username', phishtank_consts.PHISHTANK_DEFAULT_USER)}"
        }
        return phantom.APP_SUCCESS
    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_message = phishtank_consts.PHISHTANK_ERROR_MESSAGE

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.error_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_message)

        return error_text

    def handle_action(self, param):
        result = None
        action_id = self.get_action_identifier()
        if action_id == self.ACTION_ID_WHOIS_DOMAIN:
            result = self.check_url(param)
        elif action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self.test_asset_connectivity(param)
        return result

    def test_asset_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(phishtank_consts.PHISHTANK_MSG_CONNECTING)
        api_params = {'url': 'https://www.google.com', 'format': 'json'}
        if self._api_key:
            api_params[phishtank_consts.PHISHTANK_APP_KEY] = self._api_key
        time.sleep(10)
        try:
            response_code = requests.post(phishtank_consts.PHISHTANK_API_DOMAIN, data=api_params,
                                          headers=self._headers, timeout=phishtank_consts.DEFAULT_TIMEOUT).status_code
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.save_progress('test_asset_connectivity: ', error_message)
            self.save_progress(phishtank_consts.PHISHTANK_ERR_CONNECTIVITY_TEST)
            return action_result.set_status(phantom.APP_ERROR)

        if response_code != 200:
            self.save_progress(phishtank_consts.PHISHTANK_ERR_CONNECTIVITY_TEST)
            self.save_progress(phishtank_consts.PHISHTANK_SERVER_RETURNED_ERROR_CODE.format(code=response_code))
            self.save_progress(phishtank_consts.PHISHTANK_MSG_CHECK_CONNECTIVITY)
            return action_result.set_status(phantom.APP_ERROR)

        self.save_progress(phishtank_consts.PHISHTANK_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def check_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        api_params = {'url': param['url'], 'format': 'json'}
        if self._api_key:
            api_params[phishtank_consts.PHISHTANK_APP_KEY] = self._api_key

        self.save_progress(phishtank_consts.PHISHTANK_MSG_QUERY_URL,
                           query_url=param['url'])
        try:
            query_res = requests.post(phishtank_consts.
                                      PHISHTANK_API_DOMAIN,
                                      data=api_params,
                                      headers=self._headers,
                                      timeout=phishtank_consts.DEFAULT_TIMEOUT)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, phishtank_consts.PHISHTANK_SERVER_CONNECTION_ERROR,
                                            error_message)

        action_result.add_debug_data({'response_text': query_res.text if query_res else ''})
        self.debug_print('status_code', query_res.status_code)
        if query_res.status_code in [509, 429]:
            return action_result.set_status(
                                     phantom.APP_ERROR,
                                     phishtank_consts.
                                     PHISHTANK_SERVER_ERROR_RATE_LIMIT.format(str(query_res.status_code)))
        if query_res.status_code != 200:
            return action_result.set_status(
                                     phantom.APP_ERROR,
                                     phishtank_consts.
                                     PHISHTANK_SERVER_RETURNED_ERROR_CODE.
                                     format(code=query_res.status_code))
        try:
            result = query_res.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                                     phantom.APP_ERROR,
                                     error_message)

        if 'results' not in result:
            return action_result.set_status(
                phantom.APP_ERROR,
                phishtank_consts.PHISHTANK_ERR_MSG_OBJECT_QUERIED)

        status = result['results']
        action_result.append_to_message(phishtank_consts.PHISHTANK_SERVICE_SUCC_MSG)
        try:
            status_summary = {}
            if status['in_database'] is True:
                status_summary['Verified'] = status["verified"]
                status_summary['In_Database'] = status["in_database"]
                status_summary['Valid'] = status["valid"]
            else:
                if 'phish_detail_page' not in list(status.keys()):
                    status["phish_detail_page"] = None
                if 'verified_at' not in list(status.keys()):
                    status["verified_at"] = None
                if 'phish_id' not in list(status.keys()):
                    status["phish_id"] = None
                if 'valid' not in list(status.keys()):
                    status["valid"] = None
                if 'verified' not in list(status.keys()):
                    status["verified"] = None

                status_summary['Verified'] = status["verified"]
                status_summary['In_Database'] = status["in_database"]
                status_summary['Valid'] = status["valid"]
            summary.update(status_summary)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, 'Error populating summary', e)
            return action_result.get_status()

        action_result.add_data(status)
        return action_result.set_status(phantom.APP_SUCCESS)


if __name__ == '__main__':
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=phishtank_consts.DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers,
                               timeout=phishtank_consts.DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PhishtankConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)

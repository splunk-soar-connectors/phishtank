[comment]: # "Auto-generated SOAR connector documentation"
# PhishTank

Publisher: Splunk  
Connector Version: 3.0.0  
Product Vendor: OpenDNS  
Product Name: PhishTank  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.0  

This app implements URL investigative capabilities utilizing PhishTank

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the PhishTank server. Below are the default
ports used by Splunk SOAR.

|         SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a PhishTank asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  optional  | password | API key
**user_agent** |  optional  | string | User-Agent header to pass in the request e.g. (phishtank/[user_agent])  (Default: splunk_soar_user)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validates the connectivity by querying PhishTank  
[url reputation](#action-url-reputation) - Queries PhishTank for URL's phishing reputation  

## action: 'test connectivity'
Validates the connectivity by querying PhishTank

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'url reputation'
Queries PhishTank for URL's phishing reputation

Type: **investigate**  
Read only: **True**

If URL information is unavailable in PhishTank, only 'url' and 'in_database' property would be populated.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query for Phishing information | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  |   http://www.testurl.com 
action_result.data.\*.in_database | boolean |  |   False  True 
action_result.data.\*.phish_detail_page | string |  `url`  |   http://www.exampleurl.com/test_detail.php?phish_id=62001 
action_result.data.\*.phish_id | string |  |   62771 
action_result.data.\*.url | string |  `url`  |   http://www.testurl.com 
action_result.data.\*.valid | boolean |  |   False  True 
action_result.data.\*.verified | boolean |  |   False  True 
action_result.data.\*.verified_at | string |  |   2006-09-01T02:32:23+00:00 
action_result.summary.In_Database | boolean |  |   False  True 
action_result.summary.Valid | boolean |  |   False  True 
action_result.summary.Verified | boolean |  |   False  True 
action_result.message | string |  |   In database: True, Verified: False, Valid: False 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
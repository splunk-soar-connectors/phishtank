[comment]: # "Auto-generated SOAR connector documentation"
# PhishTank

Publisher: Splunk  
Connector Version: 2\.1\.1  
Product Vendor: OpenDNS  
Product Name: PhishTank  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app implements URL investigative capabilities utilizing PhishTank

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
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

If URL information is unavailable in PhishTank, only 'url' and 'in\_database' property would be populated\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query for Phishing information | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.in\_database | boolean | 
action\_result\.data\.\*\.phish\_detail\_page | string |  `url` 
action\_result\.data\.\*\.phish\_id | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.valid | boolean | 
action\_result\.data\.\*\.verified | boolean | 
action\_result\.data\.\*\.verified\_at | string | 
action\_result\.summary\.In\_Database | boolean | 
action\_result\.summary\.Valid | boolean | 
action\_result\.summary\.Verified | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
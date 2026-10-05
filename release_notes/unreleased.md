**Unreleased**

* Converted the app from BaseConnector to the Splunk SOAR SDK.
* Preserved explicit null fields in URL reputation results for URLs absent from PhishTank.
* Preserved raw validity and verification values in URL reputation data and summaries.
* Corrected the `phish_id` output type from string to numeric to match PhishTank's integer API response.
* Raised the minimum supported SOAR version from 6.1.0 to 7.0.0.
* Changed supported Python versions from 3.9/3.13 to 3.13/3.14.
* Changed the test connectivity identifier from `test_asset_connectivity` to `test_connectivity`. The displayed action name remains "test connectivity".

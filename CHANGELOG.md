# Change Log

## [3.1.9] - 2023-01-13
- Improved usage of the ServerDownOrUnreachableError exception to not lose the original message

## [3.1.8] - 2022-12-02
- Added request headers to debug log output
- Added redacting of 'Password' properties from request bodies from debug logs

## [3.1.7] - 2022-09-09
- Added handling for extracting error information when a session could not be created

## [3.1.6] - 2022-05-12
- Fixed issue where the 'read' method on response objects always return strings 
- Modified query parameter encoding to not percent-encode characters allowed in query strings per RFC3986

## [3.1.5] - 2022-04-01
- Added methods for specifying proxies directly with a new 'proxies' parameter

## [3.1.4] - 2022-03-25
- Removed enforcement of trailing '/' in the 'default_prefix'

## [3.1.3] - 2022-03-21
- Added support for Unix sockets

## [3.1.2] - 2022-03-10
- Corrected usage of header storage and retrieval for static response objects

## [3.1.1] - 2022-01-18
- Corrected 'import' statements to support Python 3.10

## [3.1.0] - 2022-01-10
- Updated library to leverage 'requests' in favor of 'http.client'

## [3.0.3] - 2021-10-15
- Added support for performing multi-part HTTP POST requests

## [3.0.2] - 2021-08-30
- Added support for prepending 'https://' when the provided URI of the service does not contain a scheme

## [3.0.1] - 2021-06-04
- Provided additional handling for HTTP 301 and 302 redirects
- Changed session creation to not follow redirects in order to ensure the session token and location are not lost
- Enhanced invalid JSON response handling to better highlight a service error

## [3.0.0] - 2021-02-20
- Removed Python2 support

## [2.2.0] - 2021-02-15
- Added support for `NO_PROXY` environment variable

## [2.1.9] - 2020-12-04
- Added handling for HTTP 303 responses as part of redirect handling

## [2.1.8] - 2020-08-10
- Added option to SSDP discover to bind to a specified address
- Added ability to override built-in HTTP headers
- Fixed issue where the location of a session was not being tracked properly for HTTP connections

## [2.1.7] - 2020-07-06
- Added support for setting the 'Content-Type' header to 'application/octet-stream' when binary data is provided in a request

## [2.1.6] - 2020-06-12
- Added support for leveraging the 'HTTP_PROXY' and 'HTTPS_PROXY' environment variables to set up proxy information

## [2.1.5] - 2020-02-03
- Removed urlparse2 dependency
- Updated jsonpatch requirements; jsonpatch 1.25 dropped Python 3.4 support

## [2.1.4] - 2020-01-10
- Added fallback to using '/redfish/v1/SessionService/Sessions' if the service root does not contains the 'Links/Sessions' property for login
- Added Python version checks to use time.perf_counter() in favor of time.clock()

## [2.1.3] - 2019-10-11
- Added IPv6 support to SSDP discovery
- Enhanced handling of poorly formatted URIs to not throw an exception

## [2.1.2] - 2019-09-16
- Fixed usage of capath and cafile when setting them to None

## [2.1.1] - 2019-08-16
- Added option in SSDP discovery to specify a particular interface
- Added sanitization to the Base URL to remove trailing slashes

## [2.1.0] - 2019-07-12
- Changed default authentication to be Session based
- Removed unnecessary closing of sockets

## [2.0.9] - 2019-06-28
- Added various unit tests and other cleanup
- Added example for how to use the 'with' statement to perform automatically log out of a service
- Made change to include the original trace when RetriesExhaustedError is encountered

## [2.0.8] - 2019-05-17
- Added helper functions for Task processing

## [2.0.7] - 2019-02-08
- Added optional timeout and max retry arguments

## [2.0.6] - 2019-01-11
- Removed usage of setting the Content-Type header to application/x-www-form-urlencoded for PUT, POST, and PATCH methods

## [2.0.5] - 2018-11-30
- Fixed handling of gzip content encoding

## [2.0.4] - 2018-10-26
- Added discovery module with SSDP support

## [2.0.3] - 2018-10-19
- Fixed handling of other successful HTTP responses (201, 202, and 204)
- Added support for being able to check the certificate of a service

## [2.0.2] - 2018-09-07
- Added handling for bad or dummy delete requests when logging out of a service

## [2.0.1] - 2018-05-25
- Adjusting setup.py to contain correct information

## [2.0.0] - 2017-07-28
- Python 3 Compatible Release

## [1.0.0] - 2017-01-12
- Initial Public Release -- supports Redfish 1.0 features

# Change Log

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

# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

import sys
import json
import redfish

# When running remotely connect using the address, account name, 
# and password to send https requests
login_host = "https://192.168.1.100"
login_account = "admin"
login_password = "password"

## Create a REDFISH object
REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                          password=login_password, default_prefix='/redfish/v1')

# Login into the server and create a session
REDFISH_OBJ.login(auth="session")

# Format parts of the Update
headers = {'Content-Type': 'multipart/form-data'}
body = {}
body['UpdateParameters'] = (None, json.dumps({'Targets': ['/redfish/v1/Managers/1'], 'Oem': {}}), 'application/json')
body['UpdateFile'] = ('flash.bin', open('flash.bin', 'rb'), 'application/octet-stream')

# The "OemXXX" part is optional in the specification
# Must be formatted as 3-tuple:
# ('filename' or None, content, content-type),
body['OemXXX'] = (None, '{"test": "value"}', 'application/json')
body['OemXXX'] = ('extra.bin', open('extra.txt', 'rb'), 'application/octet-stream')
body['OemXXX'] = ('optional.txt', open('optional.txt', 'r').read(), 'text/plain')

# Perform the POST operation
response = REDFISH_OBJ.post('/redfish/v1/upload', body=body, headers=headers)

# Print out the response
sys.stdout.write("%s\n" % response)

# Logout of the current session
REDFISH_OBJ.logout()

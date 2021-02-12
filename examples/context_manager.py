# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

import sys
import redfish

# When running remotely connect using the address, account name,
# and password to send https requests
login_host = "https://192.168.1.100"
login_account = "admin"
login_password = "password"

## Create a REDFISH object
with redfish.redfish_client(base_url=login_host, username=login_account, password=login_password) as REDFISH_OBJ:
    # Do a GET on a given path
    response = REDFISH_OBJ.get("/redfish/v1/systems/1", None)

    # Print out the response
    sys.stdout.write("%s\n" % response)

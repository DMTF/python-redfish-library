# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

import redfish

# Invoke the discovery routine for SSDP and print the responses
services = redfish.discover_ssdp()
for service in services:
    print( '{}: {}'.format(service, services[service]))

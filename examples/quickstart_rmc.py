import os
import sys
import json
import logging

from redfish import redfish_logger
from redfish.ris import RmcApp, JSONEncoder

#Config logger used by Restful library
LOGGERFILE = "RedfishApiExamples.log"
LOGGERFORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGGER = redfish_logger(LOGGERFILE, LOGGERFORMAT, logging.ERROR)
LOGGER.info("Redfish API examples")

# When running remotely connect using the address, account name, 
# and password to send https requests
login_host = "https://192.168.1.100"
login_account = "admin"
login_password = "password"

# Creating RMC object
RMCOBJ = RmcApp([])

# Create cache directory
config_dir = r'C:\DATA\redfish'
RMCOBJ.config.set_cachedir(os.path.join(config_dir, 'cache'))
cachedir = RMCOBJ.config.get_cachedir()

# If current cache exist try to log it out
if os.path.isdir(cachedir):
    RMCOBJ.logout


# Login into the server and create a session
RMCOBJ.login(username=login_account, password=login_password, \
                                                        base_url=login_host)

# Select ComputerSystems
RMCOBJ.select(['ComputerSystem.'])

# Get selected type
response = RMCOBJ.get()

# Print out the response
for item in response:
    sys.stdout.write(json.dumps(item, indent=2, cls=JSONEncoder))
    sys.stdout.write('\n')

# Logout of the current session
RMCOBJ.logout()

import sys
import redfish

# When running remotely connect using the address, account name, 
# and password to send https requests
login_host = "https://192.168.1.100"
login_account = "admin"
login_password = "password"

## Create a REDFISH object
REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, \
                          password=login_password, default_prefix='/redfish/v1')

# Login into the server and create a session
REDFISH_OBJ.login(auth="session")

# Do a GET on a given path
response = REDFISH_OBJ.get("/redfish/v1/systems/1", None)

# Print out the response
sys.stdout.write("%s\n" % response)

# Logout of the current session
REDFISH_OBJ.logout()
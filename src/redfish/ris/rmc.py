###
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md
###

# -*- coding: utf-8 -*-
"""RMC implementation """

#---------Imports---------
import os
import re
import sys
import six
import time
import copy
import shutil
import logging
from collections import OrderedDict, Mapping

import jsonpatch
import jsonpath_rw
import jsonpointer
                     
from redfish.ris.rmc_helper import (UndefinedClientError, \
                            InstanceNotFoundError, CurrentlyLoggedInError, \
                            NothingSelectedError, InvalidSelectionError, \
                            RmcClient, RmcConfig, RmcFileCacheManager, \
                            NothingSelectedSetError, LoadSkipSettingError, \
                            InvalidCommandLineError, FailureDuringCommitError, \
                            SessionExpired)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RmcApp(object):
    """Application level implementation of RMC"""
    def __init__(self, Args=None):
        """Initialize RmcApp
        
        :param Args: arguments to be passed to RmcApp
        :type Args: str
        
        """
        self._rmc_clients = []
        configfile = None
        self.logger = LOGGER

        foundsomething = False
        for item in Args:
            if foundsomething:
                configfile = item
                break

            if item == "-c":
                foundsomething = True
            elif item.startswith("--config="):
                configfile = item.split("=", 1)[1]
                break
            elif item == "--config":
                foundsomething = True

        # use the default config file
        if configfile is None:
            if os.name == 'nt':
                configfile = os.path.join(os.path.dirname(sys.executable), \
                                                                 'redfish.conf')
            else:
                configfile = '/etc/redfish/redfish.conf'

        if not os.path.isfile(configfile):
            self.warn("Config file '%s' not found\n\n" % configfile)

        self._config = RmcConfig()
        self.config_file = configfile
        self._cm = RmcFileCacheManager(self)
        self._monolith = None

        if not "--showwarnings" in Args:
            self.logger.setLevel(logging.WARNING)
            if self.logger.handlers and self.logger.handlers[0].name == 'lerr':
                self.logger.handlers.remove(self.logger.handlers[0])

    def restore(self):
        """Restore monolith from cache"""
        self._cm.uncache_rmc()

    def deletelogoutfunction(self, url=None):
        """Wrapper function for logout helper function

        :param url: The URL to perform a logout request on.
        :type url: str.

        """
        return self._cm.logout_del_function(url)

    def save(self):
        """Cache current monolith build"""
        self._cm.cache_rmc()

    def out(self):
        """Helper function for runtime error"""
        raise RuntimeError("You must override this method in your derived" \
                                                                    " class")

    def err(self, msg, inner_except=None):
        """Helper function for runtime error

        :param msg: The error message.
        :type msg: str.
        :param inner_except: The internal exception.
        :type inner_except: str.

        """
        LOGGER.error(msg)
        if inner_except is not None:
            LOGGER.error(inner_except)

    def warning_handler(self, msg):
        """Helper function for handling warning messages appropriately

        :param msg: The warning message.
        :type msg: str.

        """
        if LOGGER.getEffectiveLevel() == 40:
            sys.stderr.write(msg)
        else:
            LOGGER.warning(msg)

    def warn(self, msg, inner_except=None):
        """Helper function for runtime warning

        :param msg: The warning message.
        :type msg: str.
        :param inner_except: The internal exception.
        :type inner_except: str.

        """
        LOGGER.warning(msg)
        if inner_except is not None:
            LOGGER.warning(inner_except)

    def get_config(self):
        """Return config"""
        return self._config

    config = property(get_config, None)

    def get_cache(self):
        """Return config"""
        return self._config

    config = property(get_cache, None)

    def config_from_file(self, filename):
        """Get config from file

        :param filename: The config file name.
        :type filename: str.

        """
        self._config = RmcConfig(filename=filename)
        self._config.load()

    def add_rmc_client(self, client):
        """Add new RMC client

        :param client: The client to be added.
        :type client: str.

        """
        for i in range(0, len(self._rmc_clients)):
            if client.get_base_url() == self._rmc_clients[i].get_base_url():
                self._rmc_clients[i] = client
                return

        # not found so add it
        self._rmc_clients.append(client)

    def remove_rmc_client(self, url=None):
        """Remove RMC client

        :param url: The URL to perform the removal to.
        :type url: str.

        """
        if url:
            for i in range(0, len(self._rmc_clients)):
                if url in self._rmc_clients[i].get_base_url():
                    del self._rmc_clients[i]
        else:
            if self._rmc_clients and len(self._rmc_clients) > 0:
                self._rmc_clients = self._rmc_clients[:-1]

    def get_rmc_client(self, url):
        """Return rmc_client with the provided URL.

        :param url: The URL of the client you are searching for.
        :type url: str.

        """
        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                return self._rmc_clients[i]

        return None

    def check_current_rmc_client(self, url):
        """Return if RMC client already exists

        :param url: The URL to perform a check on.
        :type url: str.

        """
        if not len(self._rmc_clients):
            return True

        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                return True

        return False

    def update_rmc_client(self, url, **kwargs):
        """Do update to passed client

        :param url: The URL for the update request.
        :type url: str.

        """
        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                if 'username' in kwargs:
                    self._rmc_clients[i].set_username(kwargs['username'])

                if 'password' in kwargs:
                    self._rmc_clients[i].set_password(kwargs['password'])

    def get_current_client(self):
        """Get the current client"""
        if len(self._rmc_clients) > 0:
            return self._rmc_clients[-1]

        raise UndefinedClientError()

    current_client = property(get_current_client, None)

    def login(self, username=None, password=None, base_url=None, verbose=False,\
                                path=None, skipbuild=False, includelogs=False):
        """Main worker function for login command

        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param base_url: redfish host name or ip address.
        :type base_url: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param path: path to initiate login to.
        :type path: str.
        :param skipbuild: flag to determine whether to start monolith download.
        :type skipbuild: boolean.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.

        """
        if not self.check_current_rmc_client(url=base_url):
            raise CurrentlyLoggedInError("Currently logged into another " \
                                         "server. \nPlease log out out first " \
                                         "before logging in to another.")

        existing_client = self.get_rmc_client(url=base_url)
        if existing_client:
            self.update_rmc_client(url=base_url, username=username,
                                                            password=password)
        else:
            try:
                self.add_rmc_client(RmcClient(username=username, \
                                              password=password, url=base_url))
            except Exception as excp:
                raise excp

        try:
            self.current_client.login()
        except Exception as excp:
            raise excp

        if not skipbuild:
            self.build_monolith(verbose=verbose, path=path, \
                                                        includelogs=includelogs)
            self.save()

    def build_monolith(self, verbose=False, path=None, includelogs=False):
        """Run through the RIS tree to build monolith

        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param path: path to initiate login to.
        :type path: str.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.

        """
        monolith = self.current_client.monolith
        inittime = time.clock()
        monolith.load(path=path, includelogs=includelogs)
        endtime = time.clock()

        if verbose:
            sys.stdout.write("Monolith build process time: %s\n" % \
                                                        (endtime - inittime))

    def logout(self, url=None):
        """Main function for logout command

        :param url: the URL for the logout request.
        :type url: str.

        """
        sessionlocs = []
        try:
            self.current_client.monolith.killthreads()
        except Exception:
            pass

        try:
            self.current_client.logout()
        except Exception:
            sessionlocs = self.deletelogoutfunction(url)
        else:
            self.deletelogoutfunction(url)

        for session in sessionlocs:
            try:
                self.delete_handler(session[0], url=session[1], \
                            sessionid=session[2], silent=True, service=True)
            except:
                pass
        self.remove_rmc_client(url)
        self.save()

        cachedir = self.config.get_cachedir()
        if cachedir:
            try:
                shutil.rmtree(cachedir)
            except Exception:
                pass

    def get(self, selector=None):
        """Main function for get command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :returns: returns a list from get operation

        """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                jsonpath_expr = jsonpath_rw.parse('%s' % selector)
                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()

                for match in matches:
                    json_pstr = '/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node
                    results.append(temp_dict)
            else:
                results.append(currdict)

        return results

    def get_save(self, selector=None, currentoverride=False, pluspath=False, \
                                                                onlypath=None):
        """Special main function for get in save command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currentoverride: flag to override current selection.
        :type currentoverride: boolean.
        :param pluspath: flag to add path to the results.
        :type pluspath: boolean.
        :param onlypath: flag to enable only that path selection.
        :type onlypath: boolean.
        :returns: returns a list from the get command

        """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.get_save_helper(instance.resp.request.path, instances)\
                                                     and not currentoverride:
                continue
            elif onlypath:
                if not onlypath == instance.resp.request.path:
                    continue

            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                for item in six.iterkeys(currdict):
                    if selector.lower() == item.lower():
                        selector = item
                        break

                try:
                    jsonpath_expr = jsonpath_rw.parse('"%s"' % selector)
                except Exception as excp:
                    raise InvalidCommandLineError(excp)

                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()

                for match in matches:
                    json_pstr = '/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node

                results.append(temp_dict)
            else:
                if pluspath:
                    results.append({instance.resp.request.path: currdict})
                else:
                    results.append(currdict)

        return results

    def get_save_helper(self, path, instances):
        """helper function for save helper to remove non /settings section

        :param path: originating path for the current instance.
        :type path: str.
        :param instances: current retrieved instances.
        :type instances: dict.
        :returns: returns skip boolean

        """
        skip = False

        for item in instances:
            if (path + "/settings").lower() == (item.resp.request.path).lower():
                skip = True
                break
            elif (path + "settings/").lower() == \
                                            (item.resp.request.path).lower():
                skip = True
                break

        return skip

    def set(self, selector=None, val=None):
        """Main function for set command

        :param selector: the type selection for the set operation.
        :type selector: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a status or list of changes set

        """
        results = list()
        nochangesmade = False
        patchremoved = False

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        if selector:
            for instance in instances:
                if self.validate_headers(instance):
                    continue
                else:
                    nochangesmade = True

                currdict = instance.resp.dict
                for item in six.iterkeys(currdict):
                    if selector.lower() == item.lower():
                        selector = item
                        break

                newdict = currdict.copy()
                jsonpath_expr = jsonpath_rw.parse(u'%s' % selector)
                matches = jsonpath_expr.find(currdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                         "'%s', skipping '%s'\n" % (instance.type, selector))
                    nochangesmade = False

                for match in matches:
                    listfound = False
                    newdict = currdict.copy()
                    json_pstr = u'/%s' % match.full_path

                    if val:
                        if str(val)[0] == "[" and str(val)[-1] == "]":
                            json_node = jsonpointer.set_pointer(newdict, \
                                json_pstr, '"' + str(val) + '"', inplace=True)
                        else:
                            listfound = True
                    else:
                        listfound = True

                    if listfound:
                        json_node = jsonpointer.set_pointer(newdict, \
                                                json_pstr, val, inplace=True)

                    json_node = jsonpointer.resolve_pointer(newdict, json_pstr)
                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            if patch == item:
                                return

                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({selector:json_node})

                    if not patch:
                        for item in instance.patches:
                            try:
                                entry = item.patch[0]["path"].replace('/', '')
                                value = item.patch[0]["value"]
                            except Exception:
                                entry = item[0]["path"].replace('/', '')
                                value = item[0]["value"]

                            if entry == selector and str(value) not in str(val):
                                if currdict[selector] == val:
                                    instance.patches.remove(item)
                                    patchremoved = True
                                    nochangesmade = True

        if not nochangesmade:
            return "No entries found"
        if patchremoved:
            return "reverting"
        else:
            return results

    def validate_headers(self, instance, verbose=False):
        skip = False
        try:
            headervals = instance.resp._http_response.headers.keys()
            if headervals is not None and len(headervals):
                allow = list(filter(lambda x:x.lower()=="allow", headervals))
                if len(allow):
                    if not "PATCH" in instance.resp._http_response.headers\
                                                        [allow[0]]:
                        skip = True
                return skip
        except:
            pass
        try:
            if not any("PATCH" in x for x in instance.resp._http_response.msg.\
                                                                    headers):
                if verbose:
                    self.warning_handler('Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                skip = True
        except:
            try:
                for item in instance.resp._headers:
                    if list(item.keys())[0] == "allow":
                        if not "PATCH" in list(item.values())[0]:
                            if verbose:
                                self.warning_handler('Skipping read-only ' \
                                     'path: %s' % instance.resp.request.path)

                            skip = True
                            break
            except:
                if not ("allow" in instance.resp._headers and "PATCH" in \
                                            instance.resp._headers["allow"]):
                    if verbose:
                        self.warning_handler('Skipping read-only path: ' \
                                            '%s\n' % instance.resp.request.path)
                    skip = True
                elif not "allow" in instance.resp._headers:
                    if verbose:
                        self.warning_handler('Skipping read-only path: %s\n' \
                                                % instance.resp.request.path)
                    skip = True

        return skip

    def loadset(self, dicttolist=None, selector=None, val=None, newargs=None):
        """Optimized version of the old style of set properties

        :param selector: the type selection for the set operation.
        :type selector: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :returns: returns a status or a list of set properties

        """
        results = list()

        if (selector and val) and not dicttolist:
            dicttolist = [(selector, val)]
        elif dicttolist is None and not newargs:
            return results
        elif (selector and val and dicttolist) or (newargs and not val):
            return False

        nochangesmade = False
        patchremoved = False
        settingskipped = False

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        newarg = None
        if newargs:
            (name, value) = newargs[-1].split('=')
            outputline = '/'.join(newargs[:-1]) + "/" + name
            newarg = newargs[:-1]
            newarg.append(name)
            dicttolist = [(name, value)]

        for instance in instances:
            if self.validate_headers(instance):
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict
            currdictcopy = copy.deepcopy(currdict)
            templist = []

            if newargs and len(dicttolist)==1 :
                for i in range(len(newargs)):
                    for item in six.iterkeys(currdictcopy):
                        if newarg[i].lower() == item.lower():
                            newarg[i] = item

                            if not i == (len(newargs) - 1):
                                currdictcopy = currdictcopy[item]
                            else:
                                dicttolist = [(item, dicttolist[0][1])]

                            break
            else:
                items = list(currdict.keys())
                items = sorted(items)
                itemslower = [x.lower() for x in items]

                try:
                    for ind, item in enumerate(dicttolist):
                        try:
                            if not isinstance(item[1], list):
                                dicttolist[ind] = items[itemslower.index(\
                                                    item[0].lower())], item[1]
                            else:
                                templist.append(item[0])
                        except ValueError as excp:
                            self.warning_handler("Skipping property {0}, not " \
                                 "found in current server.\n".format(item[0]))

                            templist.append(item[0])
                            settingskipped = True

                    if templist:
                        dicttolist = [x for x in dicttolist if x not in \
                                                                    templist]
                except Exception as excp:
                    raise excp

            if len(dicttolist) < 1:
                return results

            newdict = copy.deepcopy(currdict)
            patch = None

            if newargs and len(dicttolist)==1 :
                matches = self.setmultiworker(newargs, dicttolist, newdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                         "'%s', skipping '%s'\n" % (instance.type, outputline))

                dicttolist = []

            for (itersel, iterval) in dicttolist:
                jsonpath_expr = jsonpath_rw.parse('%s' % itersel)
                matches = jsonpath_expr.find(currdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                             "'%s', skipping '%s'\n" % (instance.type, itersel))
                    nochangesmade = False

                for match in matches:
                    listfound = False
                    json_pstr = '/%s' % match.full_path

                    if iterval:
                        if str(iterval)[0] == "[" and str(iterval)[-1] == "]":
                            json_node = jsonpointer.set_pointer(newdict, \
                                            json_pstr, '"' + str(iterval) + \
                                            '"', inplace=True)
                        else:
                            listfound = True
                    else:
                        listfound = True

                    if listfound:
                        json_node = jsonpointer.set_pointer(newdict, \
                                            json_pstr, iterval, inplace=True)

                    json_node = jsonpointer.resolve_pointer(newdict, json_pstr)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({itersel:json_node})

                    currdict = newdict.copy()

            if newargs and not dicttolist:
                patch = jsonpatch.make_patch(currdict, newdict)

                if patch:
                    for item in instance.patches:
                        try:
                            if item[0]["path"] == patch.patch[0]["path"]:
                                instance.patches.remove(item)
                        except Exception:
                            if item.patch[0]["path"] == \
                                                    patch.patch[0]["path"]:
                                instance.patches.remove(item)

                    instance.patches.append(patch)
                    results.append({outputline:val})
                if not patch:
                    for item in instance.patches:
                        try:
                            entry = item.patch[0]["path"].split('/')[1:]
                        except Exception:
                            entry = item[0]["path"].split('/')[1:]
 
                        if len(entry) == len(newarg):
                            check = 0
                            for ind, elem in enumerate(entry):
                                if elem == newarg[ind]:
                                    check += 1
 
                            if check == len(newarg):
                                instance.patches.remove(item)
                                patchremoved = True
                                nochangesmade = True

        if not nochangesmade:
            return results
        if patchremoved:
            return "reverting"
        elif settingskipped is True:
            raise LoadSkipSettingError()
        else:
            return results

    def setmultilevel(self, val=None, newargs=None):
        """Main function for set multi level command

        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :returns: returns a status or a list of set multi level properties

        """
        results = list()
        selector = None
        nochangesmade = False
        patchremoved = False

        (name, _) = newargs[-1].split('=', 1)
        outputline = '/'.join(newargs[:-1]) + "/" + name

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        if newargs:
            for instance in instances:
                currdict = instance.resp.dict
                currdictcopy = currdict
                newarg = newargs[:-1]
                newarg.append(name)

                for i in range(len(newargs)):
                    for item in six.iterkeys(currdictcopy):
                        if newarg[i].lower() == item.lower():
                            selector = item
                            newarg[i] = item

                            if not newarg[i].lower() == newarg[-1].lower():
                                currdictcopy = currdictcopy[item]
                                break

                if not selector:
                    continue

                if self.validate_headers(instance):
                    continue
                else:
                    nochangesmade = True

                newdict = copy.deepcopy(currdict)
                self._multilevelbuffer = newdict

                matches = self.setmultiworker(newargs, self._multilevelbuffer)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                         "'%s', skipping '%s'\n" % (instance.type, outputline))
                else:
                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            if patch == item:
                                return

                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({outputline:val})

                    if not patch:
                        for item in instance.patches:
                            try:
                                entry = item.patch[0]["path"].split('/')[1:]
                            except Exception:
                                entry = item[0]["path"].split('/')[1:]

                            if len(entry) == len(newarg):
                                check = 0

                                for ind, elem in enumerate(entry):
                                    if elem == newarg[ind]:
                                        check += 1

                                if check == len(newarg):
                                    instance.patches.remove(item)
                                    patchremoved = True
                                    nochangesmade = True

        if not nochangesmade:
            return "No entries found"
        if patchremoved:
            return "reverting"
        else:
            return results

    def setmultiworker(self, newargs, change, currdict, current=0):
        """Helper function for multi level set function

        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param current: current location holder.
        :type current: list.
        :returns: returns boolean on whether properties are found

        """
        found = False

        if not newargs[current] == newargs[-1]:
            for attr, val in six.iteritems(currdict):
                if attr.lower() == newargs[current].lower():
                    current += 1
                    found = self.setmultiworker(newargs, change, val, current)
                    continue
                else:
                    continue
        else:
            for attr, val in six.iteritems(currdict):
                if attr.lower() == change[0][0].lower():
                    currdict[attr] = change[0][1]
                    found = True

        return found


    def status(self):
        """Main function for status command"""
        finalresults = list()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if 'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype]['Instances']:
                    results = list()

                    if instance.patches and len(instance.patches) > 0:
                        if isinstance(instance.patches[0], list):
                            results.extend(instance.patches)
                        else:
                            if instance.patches[0]:
                                for item in instance.patches:
                                    results.extend(item)

                    itemholder = list()
                    for mainitem in results:
                        item = copy.deepcopy(mainitem)
                        itemholder.append(item)

                    if itemholder:
                        finalresults.append({instance.type: itemholder})

        return finalresults

    def capture(self):
        """Build and return the entire monolith"""
        monolith = self.current_client.monolith
        vistedurls = monolith.get_visited_urls()

        monolith.set_visited_urls(list())
        monolith.load(includelogs=True, skipcrawl=False, loadcomplete=True)
        monolith.set_visited_urls(vistedurls)

        return monolith

    def commitworkerfunc(self, patch):
        """Helper function for the commit command

        :param patch: dictionary containing all patches to be applied.
        :type patch: dict.
        :returns: returns a dictionary of patches applied

        """
        try:
            entries = patch.patch[0]["path"][1:].split("/")
        except Exception:
            entries = patch[0]["path"][1:].split("/")

        counter = 0
        results = dict()
        for item in reversed(entries):
            if counter == 0:
                boolfound = False

                try:
                    boolfound = isinstance(patch.patch[0]["value"], bool)
                except Exception:
                    boolfound = isinstance(patch[0]["value"], bool)
                try:
                    intfound = isinstance(patch.patch[0]["value"], int)
                except Exception:
                    intfound = isinstance(patch[0]["value"], int)

                if boolfound or intfound:
                    try:
                        results = {item:patch.patch[0]["value"]}
                    except Exception:
                        results = {item:patch[0]["value"]}

                else:
                    try:
                        if patch.patch[0]["value"][0] == '"' and\
                                            patch.patch[0]["value"][-1] == '"':
                            results = {item:patch.patch[0]["value"][1:-1]}
                        else:
                            results = {item:patch.patch[0]["value"]}
                    except Exception:
                        if patch[0]["value"][0] == '"' and\
                                                patch[0]["value"][-1] == '"':
                            results = {item:patch[0]["value"][1:-1]}
                        else:
                            results = {item:patch[0]["value"]}

                counter += 1
            else:
                results = {item:results}

        return results

    def commit(self, out=sys.stdout, verbose=False):
        """Main function for commit command

        :param out: output type for verbosity.
        :type out: output type.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :returns: returns boolean of whether changes were made

        """
        changesmade = False
        instances = self.get_commit_selection()

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.validate_headers(instance, verbose=verbose):
                continue

            currdict = dict()

            # apply patches to represent current edits
            for patch in instance.patches:
                if hasattr(patch, 'patch'):
                    if len(patch.patch):
                        if "/" in patch.patch[0]["path"][1:]:
                            newdict = self.commitworkerfunc(patch)

                            if newdict:
                                self.merge_dict(currdict, newdict)
                        else:
                            if isinstance(patch.patch[0]["value"], int):
                                currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                            elif not isinstance(patch.patch[0]["value"], bool):
                                if patch.patch[0]["value"]:
                                    if patch.patch[0]["value"][0] == '"' and\
                                        patch.patch[0]["value"][-1] == '"' and\
                                        len(patch.patch[0]["value"]) == 2:
                                        currdict[patch.patch[0]["path"][1:]] = \
                                                                            ''
                                    elif patch.patch[0]["value"][0] == '"' and\
                                        patch.patch[0]["value"][-1] == '"':
                                        line = patch.patch[0]["value"]\
                                                        [2:-2].replace("'", "")
                                        line = line.replace(", ", ",")
                                        currdict[patch.patch[0]["path"]\
                                                        [1:]] = line.split(',')
                                    else:
                                        currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                                else:
                                    currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                            else:
                                currdict[patch.patch[0]["path"][1:]] = \
                                                    patch.patch[0]["value"]
                else:
                    if "/" in patch[0]["path"][1:]:
                        newdict = self.commitworkerfunc(patch)
                        if newdict:
                            self.merge_dict(currdict, newdict)
                    else:
                        if isinstance(patch[0]["value"], int):
                            currdict[patch[0]["path"][1:]] = patch[0]["value"]
                        elif not isinstance(patch[0]["value"], bool):
                            if patch[0]["value"]:
                                if patch[0]["value"][0] == '"' and\
                                            patch[0]["value"][-1] == '"' and \
                                                    len(patch[0]["value"]) == 2:
                                    currdict[patch[0]["path"][1:]] = ''
                                elif patch[0]["value"][0] == '"' and\
                                                patch[0]["value"][-1] == '"':
                                    currdict[patch[0]["path"][1:]] = \
                                            patch[0]["value"][2:-2].split(',')
                                else:
                                    currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                            else:
                                currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                        else:
                            currdict[patch[0]["path"][1:]] = patch[0]["value"]

            if currdict:
                changesmade = True
                if verbose:
                    out.write('Changes made to path: %s\n' % \
                                                    instance.resp.request.path)

                put_path = instance.resp.request.path
                results = self.current_client.set(put_path, body=currdict)

                self.invalid_return_handler(results)

                if not results.status == 200:
                    raise FailureDuringCommitError("Failed to commit with " \
                                               "error code %d" % results.status)

        return changesmade

    def merge_dict(self, currdict, newdict):
        """Helper function to merge dictionaries

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param currdict: new selection dictionary.
        :type currdict: dict.

        """
        for k, itemv2 in list(newdict.items()):
            itemv1 = currdict.get(k)

            if isinstance(itemv1, Mapping) and\
                 isinstance(itemv2, Mapping):
                self.merge_dict(itemv1, itemv2)
            else:
                currdict[k] = itemv2

    def patch_handler(self, put_path, body, verbose=False, url=None, \
                  sessionid=None, headers=None, response=False, silent=False):
        """Main worker function for raw patch command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :returns: returns RestResponse object containing response data

        """
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).set(put_path, \
                                                    body=body, headers=headers)
        else:
            results = self.current_client.set(put_path, body=body, \
                                                                headers=headers)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def get_handler(self, put_path, silent=False, verbose=False, url=None, \
                sessionid=None, uncache=False, headers=None, response=False):
        """main worker function for raw get command

        :param put_path: the URL path.
        :type put_path: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param uncache: flag to not store the data downloaded into cache.
        :type uncache: boolean.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :returns: returns a RestResponse object from client's get command

        """
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).get(put_path, \
                                                               headers=headers)
        else:
            results = self.current_client.get(put_path, uncache=uncache, \
                                                                headers=headers)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose)
        elif results.status == 401:
            raise SessionExpired()

        if results.status == 200 or response:
            return results
        else:
            return None

    def post_handler(self, put_path, body, verbose=False, url=None, \
                 sessionid=None, headers=None, response=False, silent=False):
        """Main worker function for raw post command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :returns: returns a RestResponse from client's Post command

        """
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).toolpost(\
                                        put_path, body=body, headers=headers)
        else:
            results = self.current_client.toolpost(put_path, body=body, \
                                                                headers=headers)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def put_handler(self, put_path, body, verbose=False, url=None, \
                    sessionid=None, headers=None, response=False, silent=False):
        """Main worker function for raw put command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :returns: returns a RestResponse object from client's Put command

        """
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).toolput(\
                                           put_path, body=body, headers=headers)
        else:
            results = self.current_client.toolput(put_path, body=body, \
                                                                headers=headers)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def delete_handler(self, put_path, verbose=False, url=None, \
                                    sessionid=None, headers=None, silent=True):
        """Main worker function for raw delete command

        :param put_path: the URL path.
        :type put_path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param silent: flag to disable output.
        :type silent: boolean.
        :returns: returns a RestResponse object from client's Delete command

        """
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).tooldelete(\
                                                    put_path, headers=headers)
        else:
            results = self.current_client.tooldelete(put_path, headers=headers)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose)
        elif results.status == 401:
            raise SessionExpired()

        return results

    def head_handler(self, put_path, verbose=False, url=None, sessionid=None, \
                                                                silent=False):
        """Main worker function for raw head command

        :param put_path: the URL path.
        :type put_path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :returns: returns a RestResponse object from client's Head command

        """
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).head(put_path)
        else:
            results = self.current_client.head(put_path)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose)
        elif results.status == 401:
            raise SessionExpired()

        if results.status == 200:
            return results
        else:
            return None

    _QUERY_PATTERN = re.compile(r'(?P<instance>[\w\.]+)(:(?P<xpath>.*))?')
    def _parse_query(self, querystr):
        """Parse query and return as a dict. TODO probably need to move"""
        """ this into its own class if it gets too complicated

        :param querystr: query string.
        :type querystr: str.
        :returns: returns a dict of parsed query

        """
        qmatch = RmcApp._QUERY_PATTERN.search(querystr)
        if not qmatch:
            raise InvalidSelectionError("Unable to locate instance for " \
                                                            "'%s'" % querystr)

        qgroups = qmatch.groupdict()

        return dict(instance=qgroups['instance'], \
                                            xpath=qgroups.get('xpath', None))

    def invalid_return_handler(self, results, verbose=False):
        """Main worker function for handling all error messages

        :param results: dict of the results.
        :type results: sict.
        :param verbose: flag to enable additional verbosity.
        :type verbose: boolean.

        """
        if results.status == 401:
            raise SessionExpired()
        else:
            if results.status == 200 or results.status == 201:
                if verbose:
                    self.warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                else:
                    self.warning_handler("The operation completed "\
                                                            "successfully.\n")
            else:
                self.warning_handler("[%d] No message returned.\n" % \
                                                                results.status)

    def select(self, query, sel=None, val=None):
        """Main function for select command

        :param query: query string.
        :type query: str.
        :param sel: the type selection for the select operation.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError("Unable to locate instance " \
                                                            "for '%s'" % query)
                else:
                    query = query[0]

            if val:
                if (str(val)[0] == str(val)[-1]) and \
                                                str(val).endswith(("'", '"')):
                    val = val[1:-1]

            selection = self.get_selection(selector=query, sel=sel, val=val)

            if selection and len(selection) > 0:
                self.current_client.selector = query

                if not sel is None and not val is None:
                    self.current_client.filter_attr = sel
                    self.current_client.filter_value = val
                else:
                    self.current_client.filter_attr = None
                    self.current_client.filter_value = None

                self.save()
                return selection

        if not sel is None and not val is None:
            raise InstanceNotFoundError("Unable to locate instance for" \
                                " '%s' and filter '%s=%s'" % (query, sel, val))
        else:
            raise InstanceNotFoundError("Unable to locate instance for" \
                                                                " '%s'" % query)

    def filter(self, query, sel, val):
        """Main function for filter command

        :param query: query string.
        :type query: str.
        :param sel: the type selection for the select operation.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError("Unable to locate instance " \
                                                            "for '%s'" % query)
                else:
                    query = query[0]

            selection = self.get_selection(selector=query, sel=sel, val=val)

            if selection and len(selection) > 0:
                self.current_client.selector = query
                self.current_client.filter_attr = sel
                self.current_client.filter_value = val
                self.save()

            return selection

    def filter_output(self, output, sel, val):
        """Filters a list of dictionaries based on a key:value pair

        :param output: output list.
        :type output: list.
        :param sel: the key for the property to be filtered by.
        :type sel: str.
        :param val: value for the property be filtered by.
        :type val: str.
        :returns: returns an filtered list from output parameter

        """
        newoutput = []
        if isinstance(output, list):
            for entry in output:
                if isinstance(entry, dict):
                    if '/' in sel:
                        sellist = sel.split('/')
                        newentry = copy.copy(entry)

                        for item in sellist:
                            if item in list(newentry.keys()):
                                if item == sellist[-1] and str(newentry[item])\
                                                                        == val:
                                    newoutput.append(entry)
                                else:
                                    newentry = newentry[item]
                    else:
                        if sel in list(entry.keys()) and entry[sel] == val:
                            newoutput.append(entry)
                else:
                    return output

        return newoutput

    def types(self):
        """Main function for types command

        :returns: returns a list of type strings

        """
        instances = list()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if 'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    instances.append(instance.type)

        return instances

    def get_selection(self, selector=None, sel=None, val=None):
        """Special main function for set/filter with select command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param sel: property to be modified.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if not sel and not val:
            (sel, val) = self.get_filter_settings()

        monolith = self.current_client.monolith

        instances = list()
        if not selector:
            selector = self.current_client.selector

        if not selector:
            return instances

        xpath = None
        odata = ''

        if not selector == '"*"':
            qvars = self._parse_query(selector)
            qinstance = qvars['instance']
            xpath = qvars['xpath']
        else:
            qinstance = selector

        for ristype in monolith.types:
            if 'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype]['Instances']:
                    try:
                        odata = instance.resp.dict['@odata.type'].lower()
                    except Exception:
                        odata = ''

                    if qinstance.lower() in instance.type.lower() \
                            or qinstance == '"*"' or qinstance.lower() in odata:
                        if not sel is None and not val is None:
                            currdict = instance.resp.dict

                            try:
                                if not "/" in sel:
                                    if val[-1] == "*":
                                        if not val[:-1] in str(currdict[sel]):
                                            continue
                                    else:
                                        if not str(currdict[sel]).\
                                                                startswith(val):
                                            continue
                                else:
                                    newargs = sel.split("/")
                                    content = copy.deepcopy(currdict)

                                    if self.filterworkerfunction(workdict=\
                                                content, sel=sel, val=val, \
                                                newargs=newargs, loopcount=0):
                                        instances.append(instance)
                                    continue
                            except Exception:
                                continue

                        if xpath:
                            raise RuntimeError("Not implemented")
                        else:
                            instances.append(instance)

        return instances

    def filterworkerfunction(self, workdict=None, sel=None, val=None, \
                                                    newargs=None, loopcount=0):
        """Helper function for filter application

        :param workdict: working copy of current dictionary.
        :type workdict: dict.
        :param sel: property to be modified.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param loopcount: loop count tracker.
        :type loopcount: int.
        :returns: returns boolean based on val parameter being found in newargs

        """
        if workdict and sel and val and newargs:
            if isinstance(workdict, list):
                for item in workdict:
                    if self.filterworkerfunction(workdict=item, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                        return True

                return False

            keys = list(workdict.keys())
            keyslow = [x.lower() for x in keys]

            if newargs[loopcount].lower() in keyslow:
                if loopcount == (len(newargs) - 1):
                    if val == str(workdict[newargs[loopcount]]):
                        return True

                    return False

                if not (isinstance(workdict[newargs[loopcount]], list) or \
                                isinstance(workdict[newargs[loopcount]], dict)):
                    return False

                workdict = workdict[newargs[loopcount]]
                loopcount += 1

                if self.filterworkerfunction(workdict=workdict, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                    return True

        return False

    def get_commit_selection(self):
        """Special main function for commit command"""
        instances = list()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if 'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype]['Instances']:
                    instances.append(instance)

        return instances

    def get_save_header(self, selector=None):
        """Special function for save file headers

        :param selector: the type selection for the get save operation.
        :type selector: str.
        :returns: returns an header ordered dictionary

        """
        instances = OrderedDict()
        monolith = self.current_client.monolith

        if not selector:
            selector = self.current_client.selector

        if not selector:
            return instances

        instances["Comments"] = OrderedDict()

        for ristype in monolith.types:
            if 'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype]['Instances']:
                    if "computersystem." in instance.type.lower():
                        try:
                            if instance.resp.obj["Manufacturer"]:
                                instances["Comments"]["Manufacturer"] = \
                                            instance.resp.obj["Manufacturer"]

                            if instance.resp.obj["Model"]:
                                instances["Comments"]["Model"] = \
                                                    instance.resp.obj["Model"]
                        except Exception:
                            pass

        return instances

    def get_selector(self):
        """Helper function to return current select option"""
        if self.current_client:
            if self.current_client.selector:
                return self.current_client.selector

        return None

    def get_filter_settings(self):
        """Helper function to return current select option"""
        if self.current_client:
            if not self.current_client.filter_attr is None and not \
                                    self.current_client.filter_value is None:
                return (self.current_client.filter_attr, \
                                            self.current_client.filter_value)

        return (None, None)

    def erase_filter_settings(self):
        """Helper function to return current select option"""
        if self.current_client:
            if not self.current_client.filter_attr is None or \
                                not self.current_client.filter_value is None:
                self.current_client.filter_attr = None
                self.current_client.filter_value = None

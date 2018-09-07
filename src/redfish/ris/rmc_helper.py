###
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md
###

# -*- coding: utf-8 -*-
"""RMC helper implementation"""

#---------Imports---------

import os
import json
import errno
import logging
import hashlib
import urlparse2
import redfish.rest

from .ris import (RisMonolith)
from .sharedtypes import (JSONEncoder)
from .config import (AutoConfigParser)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RdmcError(Exception):
    """Base class for all RDMC Exceptions"""
    errcode = 1
    def __init__(self, message):
        Exception.__init__(self, message)

class InvalidCommandLineError(RdmcError):
    """Raised when user enter incorrect command line arguments"""
    pass

class FailureDuringCommitError(RdmcError):
    """Raised when there is an error while updating firmware"""
    pass

class UndefinedClientError(Exception):
    """Raised when there are no clients active (usually when user hasn't logged in"""
    pass

class InstanceNotFoundError(Exception):
    """Raised when attempting to select an instance that does not exist"""
    pass

class CurrentlyLoggedInError(Exception):
    """Raised when attempting to select an instance that does not exist"""
    pass

class NothingSelectedError(Exception):
    """Raised when attempting to access an object without first selecting it"""
    pass

class NothingSelectedSetError(Exception):
    """Raised when attempting to access an object
        without first selecting it"""
    pass

class InvalidSelectionError(Exception):
    """Raised when selection argument fails to match anything"""
    pass

class SessionExpired(Exception):
    """Raised when the session has expired"""
    pass

class LoadSkipSettingError(Exception):
    """Raised when one or more settings are absent in given server"""
    pass

class InvalidPathError(Exception):
    """Raised when requested path is not found"""
    pass

class RmcClient(object):
    """RMC client base class"""
    def __init__(self, url=None, username=None, password=None, sessionkey=None):
        """Initialized RmcClient
        :param url: redfish host name or IP address.
        :type url: str.
        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param sessionkey: session key credential for current login
        :type sessionkey: str

        """
        self._rest_client = redfish.rest.v1.redfish_client(base_url=url, \
                   username=username, password=password, sessionkey=sessionkey)

        self._get_cache = dict()
        self._monolith = RisMonolith(self)
        self._selector = None
        self._filter_attr = None
        self._filter_value = None

    def get_username(self):
        """The rest client's current user name"""
        return self._rest_client.get_username()

    def set_username(self, username):
        """Sets the rest client's user name

        :param username: user name to set for login
        :type username: str

        """
        self._rest_client.set_username(username)

    def get_password(self):
        """The rest client's current password"""
        return self._rest_client.get_password()

    def set_password(self, password):
        """Sets the rest clients's password
        
        :param password: password to set for login
        :type password: str

        """
        self._rest_client.set_password(password)

    def get_session_key(self):
        """The rest client's current session key"""
        return self._rest_client.get_session_key()

    def get_session_location(self):
        """The rest client's current session location"""
        return self._rest_client.get_session_location()

    def get_authorization_key(self):
        """The rest client's current authorization key"""
        return self._rest_client.get_authorization_key()

    def get_base_url(self):
        """The rest client's current base URL"""
        return self._rest_client.get_base_url()
    base_url = property(get_base_url, None)

    def get_cache_dirname(self):
        """The rest client's current base URL converted to path"""
        parts = urlparse2.urlparse(self.get_base_url())
        pathstr = '%s/%s' % (parts.netloc, parts.path)
        return pathstr.replace('//', '/')

    def get_monolith(self):
        """The rest client's current monolith"""
        return self._monolith
    monolith = property(get_monolith, None)

    def _get_selector(self):
        """The rest client's current selector"""
        return self._selector

    def _set_selector(self, selectorval):
        """Sets the rest client's selector
        
        :param selectorval: the type selection for the set operation.
        :type selectorval: str

        """
        self._selector = selectorval
    selector = property(_get_selector, _set_selector)

    def _get_filter_attr(self):
        """The rest client's current filter"""
        return self._filter_attr

    def _set_filter_attr(self, filterattr):
        """Sets the rest client's filter
        
        :param filterattr: the type selection for the select operation.
        :type filterattr: str.
        
        """
        self._filter_attr = filterattr
    filter_attr = property(_get_filter_attr, _set_filter_attr)

    def _get_filter_value(self):
        """The rest client's current filter value"""
        return self._filter_value

    def _set_filter_value(self, filterval):
        """Sets the rest client's filter value
        
        :param filterval: value for the property to be modified.
        :type filterval: str.
        
        """
        self._filter_value = filterval
    filter_value = property(_get_filter_value, _set_filter_value)

    def login(self):
        """Login using rest client"""
        self._rest_client.login(auth="session")

    def logout(self):
        """Logout using rest client"""
        self._rest_client.logout()

    def get(self, path, args=None, uncache=False, headers=None):
        """Perform a GET request on path argument.

        :param path: The URL to perform a GET request on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :returns: a RestResponse object containing the response data.
        :rtype: redfish.rest.v1.RestResponse.
        :param uncache: flag to not store the data downloaded into cache.
        :type uncache: boolean.

        """
        resp = self._rest_client.get(path=path, args=args, headers=headers)

        if uncache is False:
            self._get_cache[path] = resp

        return resp

    def head(self, path, args=None, headers=None):
        """Perform a HEAD request on path argument.

        :param path: The URL to perform a GET request on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :returns: a RestResponse object containing the response data.
        :rtype: redfish.rest.v1.RestResponse.

        """
        resp = self._rest_client.head(path=path, args=args, headers=headers)
        return resp

    def set(self, path, args=None, body=None, headers=None):
        """Perform a PATCH request on path argument.

        :param path: The URL to perform a PATCH request on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :param body: contents of the PATCH request.
        :type body: str.
        :param headers: list of headers to be appended.
        :type headers: list.
        :returns: a RestResponse object containing the response data.
        :rtype: redfish.rest.v1.RestResponse.

        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.patch(path=path, args=args, body=body, \
                                                                headers=headers)

    def toolpost(self, path, args=None, body=None, headers=None):
        """Perform a POST request on path argument.

        :param path: The URL to perform a POST request on.
        :type path: str.
        :param args: POST arguments.
        :type args: str.
        :param body: contents of the POST request.
        :type body: str.
        :param headers: list of headers to be appended.
        :type headers: list.
        :returns: a RestResponse object containing the response data.
        :rtype: redfish.rest.v1.RestResponse.

        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.post(path=path, args=args, body=body, \
                                                                headers=headers)

    def toolput(self, path, args=None, body=None, headers=None):
        """
        Perform a PUT request on path argument.

        :param path: The URL to perform a PUT request on.
        :type path: str.
        :param args: PUT arguments.
        :type args: str.
        :param body: contents of the PUT request.
        :type body: str.
        :param headers: list of headers to be appended.
        :type headers: list.
        :returns: a RestResponse object containing the response data.
        :rtype: redfish.rest.v1.RestResponse.
        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.put(path=path, args=args, body=body, \
                                                                headers=headers)

    def tooldelete(self, path, args=None, headers=None):
        """Perform a PUT request on path argument.

        :param path: The URL to perform a DELETE request on.
        :type path: str.
        :param args: DELETE arguments.
        :type args: str.
        :param body: contents of the DELETE request.
        :type body: str.
        :param headers: list of headers to be appended.
        :type headers: list.
        :returns: a RestResponse object containing the response data.
        :rtype: redfish.rest.v1.RestResponse.

        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.delete(path=path, args=args, headers=headers)

class RmcConfig(AutoConfigParser):
    """RMC config object"""
    def __init__(self, filename=None):
        """Initialize RmcConfig
        
        :param filename: file name to be used for Rmcconfig loading.
        :type filename: str
        
        """
        AutoConfigParser.__init__(self, filename=filename)
        self._sectionname = 'redfish'
        self._configfile = filename
        self._ac__logdir = os.getcwd()
        self._ac__cache = True
        self._ac__url = ''
        self._ac__username = ''
        self._ac__password = ''
        self._ac__commit = ''
        self._ac__format = ''
        self._ac__cachedir = ''
        self._ac__savefile = ''
        self._ac__loadfile = ''

    def get_configfile(self):
        """The current configuration file"""
        return self._configfile

    def set_configfile(self, config_file):
        """Set the current configuration file 
       
        :param config_file: file name to be used for Rmcconfig loading.
        :type config_file: str
        
        """
        self._configfile = config_file

    def get_logdir(self):
        """Get the current log directory"""
        return self._get('logdir')

    def set_logdir(self, value):
        """Set the current log directory
        
        :param value: current working directory for logging
        :type value: str
        
        """
        return self._set('logdir', value)

    def get_cache(self):
        """Get the config file cache status"""
        if isinstance(self._get('cache'), bool):
            return self._get('cache')
        else:
            return self._get('cache').lower() in ("yes", "true", "t", "1")

    def set_cache(self, value):
        """Get the config file cache status
        
        :param value: status of config file cache
        :type value: bool
        
        """
        return self._set('cache', value)

    def get_url(self):
        """Get the config file URL"""
        return self._get('url')

    def set_url(self, value):
        """Set the config file URL
        
        :param value: URL path for the config file
        :type value: str
        
        """
        return self._set('url', value)

    def get_username(self):
        """Get the config file user name"""
        return self._get('username')

    def set_username(self, value):
        """Set the config file user name
        
        :param value: user name for config file
        :type value: str
        
        """
        return self._set('username', value)

    def get_password(self):
        """Get the config file password"""
        return self._get('password')

    def set_password(self, value):
        """Set the config file password
        
        :param value: password for config file
        :type value: str
        
        """
        return self._set('password', value)

    def get_commit(self):
        """Get the config file commit status"""
        return self._get('commit')

    def set_commit(self, value):
        """Set the config file commit status
        
        :param value: commit status
        :type value: str
        
        """
        return self._set('commit', value)

    def get_format(self):
        """Get the config file default format"""
        return self._get('format')

    def set_format(self, value):
        """Set the config file default format
        
        :param value: set the config file format
        :type value: str
        
        """
        return self._set('format', value)

    def get_cachedir(self):
        """Get the config file cache directory"""
        return self._get('cachedir')

    def set_cachedir(self, value):
        """Set the config file cache directory
               
        :param value: config file cache directory
        :type value: str
        
        """
        return self._set('cachedir', value)

    def get_defaultsavefilename(self):
        """Get the config file default save name"""
        return self._get('savefile')

    def set_defaultsavefilename(self, value):
        """Set the config file default save name
             
        :param value: config file save name
        :type value: str
        
        """
        return self._set('savefile', value)

    def get_defaultloadfilename(self):
        """Get the config file default load name"""
        return self._get('loadfile')

    def set_defaultloadfilename(self, value):
        """Set the config file default load name
           
        :param value: name of config file to load by default
        :type value: str
        
        """
        return self._set('loadfile', value)

class RmcCacheManager(object):
    """Manages caching/uncaching of data for RmcApp"""
    def __init__(self, rmc):
        """Initialize RmcCacheManager
        
        :param rmc: RmcApp to be managed
        :type rmc: RmcApp object
        
        """
        self._rmc = rmc

class RmcFileCacheManager(RmcCacheManager):
    """RMC file cache manager"""
    def __init__(self, rmc):
        super(RmcFileCacheManager, self).__init__(rmc)

    def logout_del_function(self, url=None):
        """Helper function for logging out a specific URL

        :param url: The URL to perform a logout request on.
        :type url: str.

        """
        cachedir = self._rmc.config.get_cachedir()
        indexfn = '%s/index' % cachedir
        sessionlocs = []

        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, 'r')
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    if url:
                        if url in index['url']:
                            os.remove(os.path.join(cachedir, index['href']))
                            break
                    else:
                        if os.path.isfile(cachedir + '/' + index['href']):
                            monolith = open(cachedir + '/' + index['href'], 'r')
                            data = json.load(monolith)
                            monolith.close()
                            for item in data:
                                if 'login' in item and 'session_location' in \
                                                                item['login']:
                                    loc = item['login']['session_location'].\
                                                split(item['login']['url'])[-1]
                                    sesurl = item['login']['url']
                                    sessionlocs.append((loc, sesurl, \
                                                item['login']['session_key']))

                        os.remove(os.path.join(cachedir, index['href']))
            except BaseException as excp:
                self._rmc.warn('Unable to read cache data %s' % excp)

        return sessionlocs

    def uncache_rmc(self):
        """Simple monolith uncache function"""
        cachedir = self._rmc.config.get_cachedir()
        indexfn = '%s/index' % cachedir

        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, 'r')
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    clientfn = index['href']
                    self._uncache_client(clientfn)
            except BaseException as excp:
                self._rmc.warn('Unable to read cache data %s' % excp)

    def _uncache_client(self, cachefn):
        """Complex monolith uncache function

        :param cachefn: The cache file name.
        :type cachefn: str.

        """
        cachedir = self._rmc.config.get_cachedir()
        clientsfn = '%s/%s' % (cachedir, cachefn)

        if os.path.isfile(clientsfn):
            try:
                clientsfh = open(clientsfn, 'r')
                clients_cache = json.load(clientsfh)
                clientsfh.close()

                for client in clients_cache:
                    if 'login' not in client:
                        continue

                    login_data = client['login']
                    if 'url' not in login_data:
                        continue

                    rmc_client = RmcClient(\
                        username=login_data.get('username', 'Administrator'), \
                        password=login_data.get('password', None), \
                        url=login_data.get('url', None), \
                        sessionkey=login_data.get('session_key', None))

                    rmc_client._rest_client.set_authorization_key(\
                                            login_data.get('authorization_key'))
                    rmc_client._rest_client.set_session_key(\
                                                login_data.get('session_key'))
                    rmc_client._rest_client.set_session_location(\
                                            login_data.get('session_location'))

                    if 'selector' in client:
                        rmc_client.selector = client['selector']

                    if 'filter_attr' in client:
                        rmc_client.filter_attr = client['filter_attr']

                    if 'filter_value' in client:
                        rmc_client.filter_value = client['filter_value']

                    getdata = client['get']
                    rmc_client._get_cache = dict()

                    for key in list(getdata.keys()):
                        restreq = redfish.rest.v1.RestRequest(\
                                                        method='GET', path=key)

                        getdata[key]['restreq'] = restreq
                        rmc_client._get_cache[key] = (\
                                  redfish.rest.v1.StaticRestResponse(\
                                                                **getdata[key]))

                    rmc_client._monolith = RisMonolith(rmc_client)
                    rmc_client._monolith.load_from_dict(client['monolith'])
                    self._rmc._rmc_clients.append(rmc_client)
            except BaseException as excp:
                self._rmc.warn('Unable to read cache data %s' % excp)

    def cache_rmc(self):
        """Caching function for monolith"""
        if not self._rmc.config.get_cache():
            return

        cachedir = self._rmc.config.get_cachedir()
        if not os.path.isdir(cachedir):
            try:
                os.makedirs(cachedir)
            except OSError as ex:
                if ex.errno == errno.EEXIST:
                    pass
                else:
                    raise

        index_map = dict()
        index_cache = list()

        for client in self._rmc._rmc_clients:
            md5 = hashlib.md5()
            md5.update(client.get_base_url().encode('utf-8'))
            md5str = md5.hexdigest()

            index_map[client.get_base_url()] = md5str
            index_data = dict(url=client.get_base_url(), href='%s' % md5str,)
            index_cache.append(index_data)

        indexfh = open('%s/index' % cachedir, 'w')
        json.dump(index_cache, indexfh, indent=2, cls=JSONEncoder)
        indexfh.close()

        clients_cache = list()

        if self._rmc._rmc_clients:
            for client in self._rmc._rmc_clients:
                login_data = dict(\
                    username=client.get_username(), \
                    password=client.get_password(), url=client.get_base_url(), \
                    session_key=client.get_session_key(), \
                    session_location=client.get_session_location(), \
                    authorization_key=client.get_authorization_key())

                clients_cache.append(\
                    dict(selector=client.selector, login=login_data, \
                         filter_attr=client._filter_attr, \
                         filter_value=client._filter_value, \
                         monolith=client.monolith, get=client._get_cache))

                clientsfh = open('%s/%s' % (cachedir, \
                                         index_map[client.get_base_url()]), 'w')

                json.dump(clients_cache, clientsfh, indent=2, cls=JSONEncoder)
                clientsfh.close()


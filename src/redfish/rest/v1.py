# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

# -*- coding: utf-8 -*-
"""Helper module for working with REST technology."""

#---------Imports---------

import os
import sys
import ssl
import time
import gzip
import json
import base64
import logging
import http.client
import re
import warnings

from collections import (OrderedDict)

from urllib.parse import urlparse, urlencode, quote
from io import StringIO
from io import BytesIO

from requests_toolbelt import MultipartEncoder

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RetriesExhaustedError(Exception):
    """Raised when retry attempts have been exhausted."""
    pass

class InvalidCredentialsError(Exception):
    """Raised when invalid credentials have been provided."""
    pass

class ServerDownOrUnreachableError(Exception):
    """Raised when server is unreachable."""
    pass

class DecompressResponseError(Exception):
    """Raised when decompressing response failed."""
    pass

class JsonDecodingError(Exception):
    """Raised when the JSON response data is malformed."""
    pass

class BadRequestError(Exception):
    """Raised when bad request made to server."""
    pass

class RisObject(dict):
    """Converts a JSON/Rest dict into a object so you can use .property
    notation"""
    __getattr__ = dict.__getitem__

    def __init__(self, d):
        """Initialize RisObject

        :param d: dictionary to be parsed
        :type d: dict

        """
        super(RisObject, self).__init__()
        self.update(**dict((k, self.parse(value)) \
                                                for k, value in d.items()))

    @classmethod
    def parse(cls, value):
        """Parse for RIS value

        :param cls: class referenced from class method
        :type cls: RisObject
        :param value: value to be parsed
        :type value: data type
        :returns: returns parsed value

        """
        if isinstance(value, dict):
            return cls(value)
        elif isinstance(value, list):
            return [cls.parse(i) for i in value]
        else:
            return value

class RestRequest(object):
    """Holder for Request information"""
    def __init__(self, path, method='GET', body=''):
        """Initialize RestRequest

        :param path: path within tree
        :type path: str
        :param method: method to be implemented
        :type method: str
        :param body: body payload for the rest call
        :type body: dict

        """
        self._path = path
        self._body = body
        self._method = method

    def _get_path(self):
        """Return object path"""
        return self._path

    path = property(_get_path, None)

    def _get_method(self):
        """Return object method"""
        return self._method

    method = property(_get_method, None)

    def _get_body(self):
        """Return object body"""
        return self._body

    body = property(_get_body, None)

    def __str__(self):
        """Format string"""
        strvars = dict(body=self.body, method=self.method, path=self.path)

        # set None to '' for strings
        if not strvars['body']:
            strvars['body'] = ''

        try:
            strvars['body'] = str(str(self._body))
        except BaseException:
            strvars['body'] = ''

        return "%(method)s %(path)s\n\n%(body)s" % strvars

class RestResponse(object):
    """Returned by Rest requests"""
    def __init__(self, rest_request, http_response):
        """Initialize RestResponse

        :params rest_request: Holder for request information
        :type rest_request: RestRequest object
        :params http_response: Response from HTTP
        :type http_response: HTTPResponse

        """
        self._read = None
        self._status = None
        self._session_key = None
        self._session_location = None
        self._task_location = None
        self._rest_request = rest_request
        self._http_response = http_response

        if self._http_response:
            self._read = self._http_response.read()
        else:
            self._read = None

    @property
    def read(self):
        """Wrapper around httpresponse.read()"""
        return self._read

    @read.setter
    def read(self, read):
        """Property for setting _read

        :param read: The data to set to read.
        :type read: str.

        """
        if read is not None:
            if isinstance(read, dict):
                read = json.dumps(read, indent=4)
            self._read = read

    def getheaders(self):
        """Property for accessing the headers"""
        return self._http_response.getheaders()

    def getheader(self, name):
        """Property for accessing an individual header

        :param name: The header name to retrieve.
        :type name: str.
        :returns: returns a header from HTTP response

        """
        return self._http_response.getheader(name, None)

    def json(self, newdict):
        """Property for setting JSON data

        :param newdict: The string data to set as JSON data.
        :type newdict: str.

        """
        self._read = json.dumps(newdict, indent=4)

    @property
    def text(self):
        """Property for accessing the data as an unparsed string"""
        if isinstance(self.read, str):
            value = self.read
        else:
            value = self.read.decode("utf-8", "ignore")
        return value

    @text.setter
    def text(self, value):
        """Property for setting text unparsed data

        :param value: The unparsed data to set as text.
        :type value: str.

        """
        self.read = value

    @property
    def dict(self):
        """Property for accessing the data as an dict"""
        try:
           return json.loads(self.text)
        except:
            str = "Service responded with invalid JSON at URI {}\n{}".format(
                self._rest_request.path, self.text)
            LOGGER.error(str)
            raise JsonDecodingError(str) from None

    @property
    def obj(self):
        """Property for accessing the data as an object"""
        return RisObject.parse(self.dict)

    @property
    def status(self):
        """Property for accessing the status code"""
        if self._status:
            return self._status

        return self._http_response.status

    @property
    def session_key(self):
        """Property for accessing the saved session key"""
        if self._session_key:
            return self._session_key

        self._session_key = self._http_response.getheader('x-auth-token')
        return self._session_key

    @property
    def session_location(self):
        """Property for accessing the saved session location"""
        if self._session_location:
            return self._session_location

        self._session_location = self._http_response.getheader('location')
        return self._session_location

    @property
    def task_location(self):
        """Return if we're a PATCH/POST in with a task link """
        if self._task_location:
            return self._task_location

        self._task_location = self._http_response.getheader('location')
        return self._task_location

    @property
    def is_processing(self):
        """Check if we're a PATCH/POST in progress """
        return self.status == 202

    @property
    def retry_after(self):
        """Retry After header"""
        return self._http_response.getheader('retry-after')

    def monitor(self, context):
        """Function to process Task, used on an action or POST/PATCH that returns 202"""
        my_href = self.task_location
        if self.is_processing:
            if my_href:
                my_content = context.get(my_href, None)
                return my_content
            elif my_href is None:
                raise ValueError('We are processing a 202, but provide no location')
        return self

    @property
    def request(self):
        """Property for accessing the saved http request"""
        return self._rest_request

    def __str__(self):
        """Class string formatter"""
        headerstr = ''
        for header in self.getheaders():
            headerstr += '%s %s\n' % (header[0], header[1])

        return "%(status)s\n%(headerstr)s\n\n%(body)s" % \
                            {'status': self.status, 'headerstr': headerstr,
                             'body': self.text}

class JSONEncoder(json.JSONEncoder):
    """JSON Encoder class"""
    def default(self, obj):
        """Set defaults in JSON encoder class

        :param obj: object to be encoded into JSON.
        :type obj: RestResponse object.
        :returns: returns a JSON ordered dict

        """
        if isinstance(obj, RestResponse):
            jsondict = OrderedDict()
            jsondict['Status'] = obj.status
            jsondict['Headers'] = list()

            for hdr in obj.getheaders():
                headerd = dict()
                headerd[hdr[0]] = hdr[1]
                jsondict['Headers'].append(headerd)

            if obj.text:
                jsondict['Content'] = obj.dict

            return jsondict

        return json.JSONEncoder.default(self, obj)

class JSONDecoder(json.JSONDecoder):
    """Custom JSONDecoder that understands our types"""
    def decode(self, json_string):
        """Decode JSON string

        :param json_string: The JSON string to be decoded into usable data.
        :type json_string: str.
        :returns: returns a parsed dict

        """
        parsed_dict = super(JSONDecoder, self).decode(json_string)
        return parsed_dict

class StaticRestResponse(RestResponse):
    """A RestResponse object used when data is being cached."""
    def __init__(self, **kwargs):
        restreq = None

        if 'restreq' in kwargs:
            restreq = kwargs['restreq']

        super(StaticRestResponse, self).__init__(restreq, None)

        if 'Status' in kwargs:
            self._status = kwargs['Status']

        if 'Headers' in kwargs:
            self._headers = kwargs['Headers']

        if 'session_key' in kwargs:
            self._session_key = kwargs['session_key']

        if 'session_location' in kwargs:
            self._session_location = kwargs['session_location']

        if 'Content' in kwargs:
            content = kwargs['Content']

            if isinstance(content, str):
                self._read = content
            else:
                self._read = json.dumps(content)
        else:
            self._read = ''

    def getheaders(self):
        """Function for accessing the headers"""
        returnlist = list()

        if isinstance(self._headers, dict):
            for key, value in self._headers.items():
                returnlist.append((key, value))
        else:
            for item in self._headers:
                returnlist.append(item.items()[0])

        return returnlist

class AuthMethod(object):
    """AUTH Method class"""
    BASIC = 'basic'
    SESSION = 'session'

class RestClientBase(object):
    """Base class for RestClients"""

    def __init__(self, base_url, username=None, password=None,
                                default_prefix='/redfish/v1/', sessionkey=None,
                                capath=None, cafile=None, timeout=None,
                                max_retry=None):
        """Initialization of the base class RestClientBase

        :param base_url: The URL of the remote system
        :type base_url: str
        :param username: The user name used for authentication
        :type username: str
        :param password: The password used for authentication
        :type password: str
        :param default_prefix: The default root point
        :type default_prefix: str
        :param sessionkey: session key for the current login of base_url
        :type sessionkey: str
        :param capath: Path to a directory containing CA certificates
        :type capath: str
        :param cafile: Path to a file of CA certs
        :type cafile: str
        :param timeout: Timeout in seconds for the initial connection
        :type timeout: int
        :param max_retry: Number of times a request will retry after a timeout
        :type max_retry: int

        """

        self.__base_url = base_url.rstrip('/')
        self.__username = username
        self.__password = password
        self.__url = urlparse(self.__base_url)
        self.__session_key = sessionkey
        self.__authorization_key = None
        self.__session_location = None
        self._conn = None
        self._conn_count = 0
        self._timeout = timeout
        self._max_retry = max_retry if max_retry is not None else 10
        self.login_url = None
        self.default_prefix = default_prefix
        self.capath = capath
        self.cafile = cafile

        self.__init_connection()
        self.get_root_object()
        self.__destroy_connection()

    @staticmethod
    def _bypass_proxy(host):
        """
        Read NO_PROXY environment variable to determine if proxy should be
        bypassed for host.

        :param host: the host to check
        :return: True is proxy should be bypassed, False otherwise
        """
        if 'NO_PROXY' in os.environ:
            no_proxy = os.environ['NO_PROXY']
            if no_proxy == '*':
                return True
            hostonly = host.rsplit(':', 1)[0]  # without port
            no_proxy_list = [proxy.strip() for proxy in no_proxy.split(',')]
            for name in no_proxy_list:
                if name:
                    name = name.lstrip('.')  # ignore leading dots
                    name = re.escape(name)
                    pattern = r'(.+\.)?%s$' % name
                    if (re.match(pattern, hostonly, re.I)
                            or re.match(pattern, host, re.I)):
                        print('returning true (re)')
                        return True
        return False

    def _get_connection(self, url, **kwargs):
        """
        Wrapper function for the HTTPSConnection/HTTPConnection constructor
        that handles proxies set by the HTTPS_PROXY and HTTP_PROXY environment
        variables

        :param url: the target URL
        :param kwargs: keyword arguments for the connection constructor
        :return: the connection
        """
        bypass_proxy = self._bypass_proxy(url.netloc)
        proxy = None
        if url.scheme.upper() == "HTTPS":
            connection = http.client.HTTPSConnection
            if not bypass_proxy and 'HTTPS_PROXY' in os.environ:
                host = urlparse(os.environ['HTTPS_PROXY']).netloc
                proxy = url.netloc
            else:
                host = url.netloc
        else:
            connection = http.client.HTTPConnection
            if not bypass_proxy and 'HTTP_PROXY' in os.environ:
                host = urlparse(os.environ['HTTP_PROXY']).netloc
                proxy = url.netloc
            else:
                host = url.netloc
        conn = connection(host, **kwargs)
        if proxy:
            LOGGER.debug("Proxy %s connection to %s through %s" % (
                url.scheme.upper(), proxy, host))
            conn.set_tunnel(proxy)
        return conn

    def __init_connection(self, url=None):
        """Function for initiating connection with remote server

        :param url: The URL of the remote system
        :type url: str

        """
        self.__destroy_connection()

        url = url if url else self.__url
        if url.scheme.upper() == "HTTPS":
            if self.cafile or self.capath is not None:
                ssl_context = ssl.create_default_context(capath=self.capath,
                                                         cafile=self.cafile)
            else:
                ssl_context = ssl._create_unverified_context()
            self._conn = self._get_connection(url, context=ssl_context,
                                              timeout=self._timeout)
        elif url.scheme.upper() == "HTTP":
            self._conn = self._get_connection(url, timeout=self._timeout)
        else:
            pass

    def __destroy_connection(self):
        """Function for closing connection with remote server"""
        if self._conn:
            self._conn.close()

        self._conn = None
        self._conn_count = 0

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.logout()
        self.__destroy_connection()

    def get_username(self):
        """Return used user name"""
        return self.__username

    def set_username(self, username):
        """Set user name

        :param username: The user name to be set.
        :type username: str

        """
        self.__username = username

    def get_password(self):
        """Return used password"""
        return self.__password

    def set_password(self, password):
        """Set password

        :param password: The password to be set.
        :type password: str

        """
        self.__password = password

    def get_base_url(self):
        """Return used URL"""
        return self.__base_url

    def set_base_url(self, url):
        """Set based URL

        :param url: The URL to be set.
        :type url: str

        """
        self.__base_url = url.rstrip('/')

    def get_session_key(self):
        """Return session key"""
        return self.__session_key

    def set_session_key(self, session_key):
        """Set session key

        :param session_key: The session_key to be set.
        :type session_key: str

        """
        self.__session_key = session_key

    def get_session_location(self):
        """Return session location"""
        return self.__session_location

    def set_session_location(self, session_location):
        """Set session location

        :param session_location: The session_location to be set.
        :type session_location: str

        """
        self.__session_location = session_location

    def get_authorization_key(self):
        """Return authorization key"""
        return self.__authorization_key

    def set_authorization_key(self, authorization_key):
        """Set authorization key

        :param authorization_key: The authorization_key to be set.
        :type authorization_key: str

        """
        self.__authorization_key = authorization_key

    def get_root_object(self):
        """Perform an initial get and store the result"""
        try:
            resp = self.get('%s%s' % (self.__url.path, self.default_prefix))
        except Exception as excp:
            raise excp

        if resp.status != 200:
            raise ServerDownOrUnreachableError("Server not reachable, " \
                                               "return code: %d" % resp.status)

        content = resp.text

        try:
            root_data = json.loads(content)
        except:
            str = 'Service responded with invalid JSON at URI {}{}\n{}'.format(
                self.__url.path, self.default_prefix, content)
            LOGGER.error(str)
            raise JsonDecodingError(str) from None

        self.root = RisObject.parse(root_data)
        self.root_resp = resp

    def get(self, path, args=None, headers=None):
        """Perform a GET request

        :param path: the URL path.
        :type path: str.
        :param args: the arguments to get.
        :type args: dict.
        :param headers: dict of headers to be appended.
        :type headers: dict.
        :returns: returns a rest request with method 'Get'

        """
        try:
            return self._rest_request(path, method='GET', args=args,
                                                                headers=headers)
        except ValueError:
            str = "Service responded with invalid JSON at URI {}".format(path)
            LOGGER.error(str)
            raise JsonDecodingError(str) from None

    def head(self, path, args=None, headers=None):
        """Perform a HEAD request

        :param path: the URL path.
        :type path: str.
        :param args: the arguments to get.
        :type args: dict.
        :param headers: dict of headers to be appended.
        :type headers: dict.
        :returns: returns a rest request with method 'Head'

        """
        return self._rest_request(path, method='HEAD', args=args,
                                                                headers=headers)

    def post(self, path, args=None, body=None, headers=None):
        """Perform a POST request

        :param path: the URL path.
        :type path: str.
        :param args: the arguments to post.
        :type args: dict.
        :param body: the body to the sent.
        :type body: str.
        :param headers: dict of headers to be appended.
        :type headers: dict.
        :returns: returns a rest request with method 'Post'

        """
        return self._rest_request(path, method='POST', args=args, body=body,
                                                                headers=headers)

    def put(self, path, args=None, body=None, headers=None):
        """Perform a PUT request

        :param path: the URL path.
        :type path: str.
        :param args: the arguments to put.
        :type args: dict.
        :param body: the body to the sent.
        :type body: str.
        :param headers: dict of headers to be appended.
        :type headers: dict.
        :returns: returns a rest request with method 'Put'

        """
        return self._rest_request(path, method='PUT', args=args, body=body,
                                                                headers=headers)

    def patch(self, path, args=None, body=None, headers=None):
        """Perform a PUT request

        :param path: the URL path.
        :type path: str.
        :param args: the arguments to patch.
        :type args: dict.
        :param body: the body to the sent.
        :type body: str.
        :param headers: dict of headers to be appended.
        :type headers: dict.
        :returns: returns a rest request with method 'Patch'

        """
        return self._rest_request(path, method='PATCH', args=args, body=body,
                                                                headers=headers)

    def delete(self, path, args=None, headers=None):
        """Perform a DELETE request

        :param path: the URL path.
        :type path: str.
        :param args: the arguments to delete.
        :type args: dict.
        :param headers: dict of headers to be appended.
        :type headers: dict.
        :returns: returns a rest request with method 'Delete'

        """
        return self._rest_request(path, method='DELETE', args=args,
                                                                headers=headers)

    def _get_req_headers(self, headers=None):
        """Get the request headers

        :param headers: additional headers to be utilized
        :type headers: dict
        :returns: returns headers

        """
        headers = headers if isinstance(headers, dict) else dict()

        if self.__session_key:
            headers['X-Auth-Token'] = self.__session_key
        elif self.__authorization_key:
            headers['Authorization'] = self.__authorization_key

        headers_keys = set(k.lower() for k in headers)
        if 'accept' not in headers_keys:
            headers['Accept'] = '*/*'

        headers['Connection'] = 'Keep-Alive'

        return headers

    def _rest_request(self, path, method='GET', args=None, body=None,
                      headers=None, skip_redirect=False):
        """Rest request main function

        :param path: path within tree
        :type path: str
        :param method: method to be implemented
        :type method: str
        :param args: the arguments for method
        :type args: dict
        :param body: body payload for the rest call
        :type body: dict
        :param headers: provide additional headers
        :type headers: dict
        :param skip_redirect: controls whether redirects are followed
        :type skip_redirect: bool
        :returns: returns a RestResponse object

        """
        headers = self._get_req_headers(headers)
        reqpath = path.replace('//', '/')

        if body is not None:
            if isinstance(body, dict) or isinstance(body, list):
                if headers.get('Content-Type', None) == 'multipart/form-data':
                    # Body contains part values, either as
                    # - dict (where key is part name, and value is string)
                    # - list of tuples (if the order is important)
                    # - dict (where values are tuples as they would
                    #   be provided to requests' `files` parameter)
                    # See https://toolbelt.readthedocs.io/en/latest/uploading-data.html#requests_toolbelt.multipart.encoder.MultipartEncoder
                    #
                    # Redfish specification requires two parts:
                    # (1) UpdateParameters (JSON formatted,
                    #     adhering to the UpdateService Schema)
                    # (2) UpdateFile (binary file to use for this update)
                    #
                    # The third part is optional: OemXXX
                    encoder = MultipartEncoder(body)
                    body = encoder.to_string()

                    # Overwrite Content-Type, because we have to include
                    # the boundary that the encoder generated.
                    # Will be of the form: "multipart/form-data; boundary=abc'
                    # where the boundary value is a UUID.
                    headers['Content-Type'] = encoder.content_type
                else:
                    headers['Content-Type'] = 'application/json'
                    body = json.dumps(body)
            elif isinstance(body, bytes):
                headers['Content-Type'] = 'application/octet-stream'
                body = body
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = urlencode(body)

            if method == 'PUT':
                resp = self._rest_request(path=path)

                try:
                    if resp.getheader('content-encoding') == 'gzip':
                        buf = StringIO()
                        gfile = gzip.GzipFile(mode='wb', fileobj=buf)

                        try:
                            gfile.write(str(body))
                        finally:
                            gfile.close()

                        compresseddata = buf.getvalue()
                        if compresseddata:
                            data = bytearray()
                            data.extend(memoryview(compresseddata))
                            body = data
                except BaseException as excp:
                    LOGGER.error('Error occur while compressing body: %s', excp)
                    raise

            headers['Content-Length'] = len(body)

        if args:
            if method == 'GET':
                # Workaround for this bug: https://bugs.python.org/issue18857
                none_list = []
                args_copy = {}
                for query in args:
                    if args[query] is None:
                        none_list.append(query)
                    else:
                        args_copy[query] = args[query]
                reqpath += '?' + urlencode(args_copy, quote_via=quote)
                for query in none_list:
                    if reqpath[-1] == '?':
                        reqpath += query
                    else:
                        reqpath += '&' + query
            elif method == 'PUT' or method == 'POST' or method == 'PATCH':
                LOGGER.warning('For POST, PUT and PATCH methods, the provided "args" parameter "{}" is ignored.'
                               .format(args))
                if not body:
                    LOGGER.warning('Use the "body" parameter to supply the request payload.')

        restreq = RestRequest(reqpath, method=method, body=body)

        attempts = 0
        restresp = None
        cause_exception = None
        while attempts <= self._max_retry:
            if LOGGER.isEnabledFor(logging.DEBUG):
                try:
                    logbody = None
                    if restreq.body:
                        if restreq.body[0] == '{':
                            logbody = restreq.body
                        else:
                            raise ValueError('Body of message is binary')
                    LOGGER.debug('HTTP REQUEST: %s\n\tPATH: %s\n\tBODY: %s'% \
                                    (restreq.method, restreq.path, logbody))
                except:
                    LOGGER.debug('HTTP REQUEST: %s\n\tPATH: %s\n\tBODY: %s'% \
                                (restreq.method, restreq.path, 'binary body'))
            attempts = attempts + 1
            LOGGER.info('Attempt %s of %s', attempts, path)

            try:
                while True:
                    if self._conn is None:
                        self.__init_connection()

                    self._conn.request(method.upper(), reqpath, body=body,
                                                                headers=headers)
                    self._conn_count += 1

                    if sys.version_info < (3, 3):
                        inittime = time.clock()
                    else:
                        inittime = time.perf_counter()
                    resp = self._conn.getresponse()
                    if sys.version_info < (3, 3):
                        endtime = time.clock()
                    else:
                        endtime = time.perf_counter()
                    LOGGER.info('Response Time for %s to %s: %s seconds.' %
                                (method, reqpath, str(endtime-inittime)))

                    if resp.getheader('Connection') == 'close':
                        self.__destroy_connection()

                    # redirect handling
                    if resp.status not in list(range(300, 399)) or \
                       resp.status == 304 or skip_redirect is True:
                        break
                    newloc = resp.getheader('location')
                    newurl = urlparse(newloc)
                    if resp.status in [301, 302, 303]:
                        method = 'GET'
                        body = None
                        for h in ['Content-Type', 'Content-Length']:
                            if h in headers:
                                del headers[h]

                    reqpath = newurl.path
                    self.__init_connection(newurl)

                restresp = RestResponse(restreq, resp)

                try:
                    if restresp.getheader('content-encoding') == "gzip":
                        compressedfile = BytesIO(restresp.read)
                        decompressedfile = gzip.GzipFile(fileobj=compressedfile)
                        restresp.text = decompressedfile.read().decode("utf-8")
                except Exception as excp:
                    LOGGER.error('Error occur while decompressing body: %s',
                                                                        excp)
                    raise DecompressResponseError()
            except Exception as excp:
                if isinstance(excp, DecompressResponseError):
                    raise

                if not cause_exception:
                    cause_exception = excp
                LOGGER.info('Retrying %s [%s]'% (path, excp))
                time.sleep(1)

                self.__init_connection()
                continue
            else:
                break

        if attempts <= self._max_retry:
            if LOGGER.isEnabledFor(logging.DEBUG):
                headerstr = ''

                if restresp is not None:
                    for header in restresp.getheaders():
                        headerstr += '\t' + header[0] + ': ' + header[1] + '\n'

                    try:
                        LOGGER.debug('HTTP RESPONSE for %s:\nCode: %s\nHeaders:\n' \
                                 '%s\nBody Response of %s: %s'%\
                                 (restresp.request.path,
                                str(restresp._http_response.status)+ ' ' + \
                                restresp._http_response.reason,
                                headerstr, restresp.request.path, restresp.read))
                    except:
                        LOGGER.debug('HTTP RESPONSE:\nCode:%s', restresp)
                else:
                    LOGGER.debug('HTTP RESPONSE: <No HTTP Response obtained>')

            return restresp
        else:
            raise RetriesExhaustedError() from cause_exception

    def login(self, username=None, password=None, auth=AuthMethod.SESSION):
        """Login and start a REST session.  Remember to call logout() when"""
        """ you are done.

        :param username: the user name.
        :type username: str.
        :param password: the password.
        :type password: str.
        :param auth: authentication method
        :type auth: object/instance of class AuthMethod

        """

        self.__username = username if username else self.__username
        self.__password = password if password else self.__password

        if auth == AuthMethod.BASIC:
            auth_key = base64.b64encode(('%s:%s' % (self.__username,
                            self.__password)).encode('utf-8')).decode('utf-8')
            self.__authorization_key = 'Basic %s' % auth_key

            headers = dict()
            headers['Authorization'] = self.__authorization_key

            respvalidate = self._rest_request('%s%s' % (self.__url.path,
                                            self.login_url), headers=headers)

            if respvalidate.status == 401:
                #If your REST client has a delay for fail attempts add it here
                delay = 0
                raise InvalidCredentialsError(delay)
        elif auth == AuthMethod.SESSION:
            data = dict()
            data['UserName'] = self.__username
            data['Password'] = self.__password

            headers = dict()
            resp = self._rest_request(self.login_url, method="POST",body=data,
                                      headers=headers, skip_redirect=True)

            LOGGER.info('Login returned code %s: %s', resp.status, resp.text)

            self.__session_key = resp.session_key
            self.__session_location = resp.session_location

            if not self.__session_key and resp.status not in [200, 201, 202, 204]:
                #If your REST client has a delay for fail attempts added it here
                delay = 0
                raise InvalidCredentialsError(delay)
            else:
                self.set_username(None)
                self.set_password(None)
        else:
            pass

    def logout(self):
        """ Logout of session. YOU MUST CALL THIS WHEN YOU ARE DONE TO FREE"""
        """ UP SESSIONS"""
        if self.__session_key:
            session_loc = urlparse(self.__session_location).path

            resp = self.delete(session_loc)
            if resp.status not in [200, 202, 204]:
                raise BadRequestError("Invalid session resource: %s, "\
                                   "return code: %d" % (session_loc, resp.status))

            LOGGER.info("User logged out: %s", resp.text)

            self.__session_key = None
            self.__session_location = None
            self.__authorization_key = None

class HttpClient(RestClientBase):
    """A client for Rest"""
    def __init__(self, base_url, username=None, password=None,
                                default_prefix='/redfish/v1/',
                                sessionkey=None, capath=None,
                                cafile=None, timeout=None,
                                max_retry=None):
        """Initialize HttpClient

        :param base_url: The url of the remote system
        :type base_url: str
        :param username: The user name used for authentication
        :type username: str
        :param password: The password used for authentication
        :type password: str
        :param default_prefix: The default root point
        :type default_prefix: str
        :param sessionkey: session key for the current login of base_url
        :type sessionkey: str
        :param capath: Path to a directory containing CA certificates
        :type capath: str
        :param cafile: Path to a file of CA certs
        :type cafile: str
        :param timeout: Timeout in seconds for the initial connection
        :type timeout: int
        :param max_retry: Number of times a request will retry after a timeout
        :type max_retry: int

        """
        super(HttpClient, self).__init__(base_url, username=username,
                            password=password, default_prefix=default_prefix,
                            sessionkey=sessionkey, capath=capath,
                            cafile=cafile, timeout=timeout,
                            max_retry=max_retry)

        try:
            self.login_url = self.root.Links.Sessions['@odata.id']
        except KeyError:
            # While the "Links/Sessions" property is required, we can fallback
            # on the URI hardened in 1.6.0 of the specification if not found
            LOGGER.debug('"Links/Sessions" not found in Service Root.')
            self.login_url = '/redfish/v1/SessionService/Sessions'

    def _rest_request(self, path='', method="GET", args=None, body=None,
                      headers=None, skip_redirect=False):
        """Rest request for HTTP client

        :param path: path within tree
        :type path: str
        :param method: method to be implemented
        :type method: str
        :param args: the arguments for method
        :type args: dict
        :param body: body payload for the rest call
        :type body: dict
        :param headers: provide additional headers
        :type headers: dict
        :param skip_redirect: controls whether redirects are followed
        :type skip_redirect: bool
        :returns: returns a rest request

        """
        if self.default_prefix == path and path[-1] != '/':
            path = path + '/'
        else:
            pass

        return super(HttpClient, self)._rest_request(path=path, method=method,
                                                     args=args, body=body,
                                                     headers=headers,
                                                     skip_redirect=skip_redirect)

    def _get_req_headers(self, headers=None, providerheader=None):
        """Get the request headers for HTTP client

        :param headers: additional headers to be utilized
        :type headers: dict
        :returns: returns request headers

        """
        headers = super(HttpClient, self)._get_req_headers(headers)
        headers_keys = set(k.lower() for k in headers)
        if 'odata-version' not in headers_keys:
            headers['OData-Version'] = '4.0'

        return headers

def redfish_client(base_url=None, username=None, password=None,
                                default_prefix='/redfish/v1/',
                                sessionkey=None, capath=None,
                                cafile=None, timeout=None,
                                max_retry=None):
    """Create and return appropriate REDFISH client instance."""
    """ Instantiates appropriate Redfish object based on existing"""
    """ configuration. Use this to retrieve a pre-configured Redfish object

    :param base_url: rest host or ip address.
    :type base_url: str.
    :param username: user name required to login to server
    :type: str
    :param password: password credentials required to login
    :type password: str
    :param default_prefix: default root to extract tree
    :type default_prefix: str
    :param sessionkey: session key credential for current login
    :type sessionkey: str
    :param capath: Path to a directory containing CA certificates
    :type capath: str
    :param cafile: Path to a file of CA certs
    :type cafile: str
    :param timeout: Timeout in seconds for the initial connection
    :type timeout: int
    :param max_retry: Number of times a request will retry after a timeout
    :type max_retry: int
    :returns: a client object.

    """
    if "://" not in base_url:
        warnings.warn("Scheme not specified for '{}'; adding 'https://'".format(base_url))
        base_url = "https://" + base_url
    return HttpClient(base_url=base_url, username=username, password=password,
                        default_prefix=default_prefix, sessionkey=sessionkey,
                        capath=capath, cafile=cafile, timeout=timeout,
                        max_retry=max_retry)

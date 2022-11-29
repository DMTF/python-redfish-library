# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

# -*- coding: utf-8 -*-
"""Helper module for working with REST technology."""

#---------Imports---------

import sys
import time
import gzip
import json
import base64
import logging
import warnings
import re
import requests
import requests_unixsocket

from collections import (OrderedDict)

from urllib.parse import urlparse, urlencode, quote
from io import StringIO

from requests_toolbelt import MultipartEncoder

# Many services come with self-signed certificates and will remain as such; need to suppress warnings for this
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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

class SessionCreationError(Exception):
    """Raised when a session could not be created."""
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
        :type http_response: requests.Response

        """
        self._read = None
        self._status = None
        self._session_key = None
        self._session_location = None
        self._task_location = None
        self._rest_request = rest_request
        self._http_response = http_response

        if http_response is not None:
            self._read = http_response.content
            self._status = http_response.status_code

    @property
    def read(self):
        """Property for accessing raw content as an array of bytes (unless overridden)

        TODO: Need to review usage elsewhwere; by default _read is an array of bytes, but applying a new value with a
        setter routine will make it a string.  We might want to consider deprecating the setters.
        """
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

        # Backwards compatibility: requests simply uses a dictionary, but older versions of this library returned a list of tuples
        headers = []
        for header in self._http_response.headers:
            headers.append((header, self._http_response.headers[header]))
        return headers

    def getheader(self, name):
        """Property for accessing an individual header

        :param name: The header name to retrieve.
        :type name: str.
        :returns: returns a header from HTTP response

        """
        return self._http_response.headers.get(name.lower(), None)

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
        return self._status

    @property
    def session_key(self):
        """Property for accessing the saved session key"""
        if self._session_key:
            return self._session_key

        self._session_key = self.getheader('x-auth-token')
        return self._session_key

    @property
    def session_location(self):
        """Property for accessing the saved session location"""
        if self._session_location:
            return self._session_location

        self._session_location = self.getheader('location')
        return self._session_location

    @property
    def task_location(self):
        """Return if we're a PATCH/POST in with a task link """
        if self._task_location:
            return self._task_location

        self._task_location = self.getheader('location')
        return self._task_location

    @property
    def is_processing(self):
        """Check if we're a PATCH/POST in progress """
        return self.status == 202

    @property
    def retry_after(self):
        """Retry After header"""
        retry_after = self.getheader('retry-after')
        if retry_after is not None:
            # Convert to int for ease of use by callers
            try:
                retry_after = int(retry_after)
            except:
                retry_after = 5
        return retry_after

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
                returnlist.append(item)

        return returnlist

    def getheader(self, name):
        """Property for accessing an individual header

        :param name: The header name to retrieve.
        :type name: str.
        :returns: returns a header from HTTP response
        """
        returnheader = None

        if isinstance(self._headers, dict):
            for key, value in self._headers.items():
                if key.lower() == name.lower():
                    returnheader = self._headers[key]
                    break
        else:
            for item in self._headers:
                if item[0].lower() == name.lower():
                    returnheader = item[1]
                    break

        return returnheader

class AuthMethod(object):
    """AUTH Method class"""
    BASIC = 'basic'
    SESSION = 'session'

class RestClientBase(object):
    """Base class for RestClients"""

    def __init__(self, base_url, username=None, password=None,
                                default_prefix='/redfish/v1/', sessionkey=None,
                                capath=None, cafile=None, timeout=None,
                                max_retry=None, proxies=None):
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
        :param proxies: Dictionary containing protocol to proxy URL mappings
        :type proxies: dict

        """

        self.__base_url = base_url.rstrip('/')
        self.__username = username
        self.__password = password
        self.__session_key = sessionkey
        self.__authorization_key = None
        self.__session_location = None
        if self.__base_url.startswith('http+unix://'):
            self._session = requests_unixsocket.Session()
        else:
            self._session = requests.Session()
        self._timeout = timeout
        self._max_retry = max_retry if max_retry is not None else 10
        self._proxies = proxies
        self.login_url = None
        self.default_prefix = default_prefix
        self.capath = capath
        self.cafile = cafile
        self.get_root_object()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.logout()

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
            resp = self.get(self.default_prefix)
        except Exception as excp:
            raise excp

        if resp.status != 200:
            raise ServerDownOrUnreachableError("Server not reachable, " \
                                               "return code: %d" % resp.status)

        content = resp.text

        try:
            root_data = json.loads(content)
        except:
            str = 'Service responded with invalid JSON at URI {}\n{}'.format(
                self.default_prefix, content)
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

        return headers

    def _rest_request(self, path, method='GET', args=None, body=None,
                      headers=None, allow_redirects=True):
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
        :param allow_redirects: controls whether redirects are followed
        :type allow_redirects: bool
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

        query_str = None
        if args:
            if method == 'GET':
                # Workaround for this: https://github.com/psf/requests/issues/993
                # Redfish supports some query parameters without using '=', which is apparently against HTML5
                none_list = []
                args_copy = {}
                for query in args:
                    if args[query] is None:
                        none_list.append(query)
                    else:
                        args_copy[query] = args[query]
                query_str = urlencode(args_copy, quote_via=quote, safe="/?:!$'()*+,;\\=")
                for query in none_list:
                    if len(query_str) == 0:
                        query_str += query
                    else:
                        query_str += '&' + query
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
                headerstr = ''
                if headers is not None:
                    for header in headers:
                        if header.lower() == "authorization":
                            headerstr += '\t{}: <REDACTED>\n'.format(header)
                        else:
                            headerstr += '\t{}: {}\n'.format(header, headers[header])
                try:
                    logbody = 'No request body'
                    if restreq.body:
                        if restreq.body[0] == '{':
                            # Mask password properties
                            # NOTE: If the password itself contains a double quote, it will not redact the entire password
                            logbody = re.sub('"Password"\s*:\s*".*?"', '"Password": "<REDACTED>"', restreq.body)
                        else:
                            raise ValueError('Body of message is binary')
                    LOGGER.debug('HTTP REQUEST (%s) for %s:\nHeaders:\n%s\nBody: %s\n'% \
                                 (restreq.method, restreq.path, headerstr, logbody))
                except:
                    LOGGER.debug('HTTP REQUEST (%s) for %s:\nHeaders:\n%s\nBody: %s\n'% \
                                 (restreq.method, restreq.path, headerstr, 'binary body'))
            attempts = attempts + 1
            LOGGER.info('Attempt %s of %s', attempts, path)

            try:
                if sys.version_info < (3, 3):
                    inittime = time.clock()
                else:
                    inittime = time.perf_counter()

                # TODO: Migration to requests lost the "CA directory" capability; need to revisit
                verify = False
                if self.cafile:
                    verify = self.cafile
                resp = self._session.request(method.upper(), "{}{}".format(self.__base_url, reqpath), data=body,
                                             headers=headers, timeout=self._timeout, allow_redirects=allow_redirects,
                                             verify=verify, proxies=self._proxies, params=query_str)

                if sys.version_info < (3, 3):
                    endtime = time.clock()
                else:
                    endtime = time.perf_counter()
                LOGGER.info('Response Time for %s to %s: %s seconds.' %
                            (method, reqpath, str(endtime-inittime)))

                restresp = RestResponse(restreq, resp)
            except Exception as excp:
                if not cause_exception:
                    cause_exception = excp
                LOGGER.info('Retrying %s [%s]'% (path, excp))
                time.sleep(1)

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
                        LOGGER.debug('HTTP RESPONSE for %s:\nCode: %s\n\nHeaders:\n' \
                                 '%s\nBody Response of %s: %s\n'%\
                                 (restresp.request.path,
                                str(restresp._http_response.status_code)+ ' ' + \
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

            respvalidate = self._rest_request(self.login_url, headers=headers)

            if respvalidate.status == 401:
                # Invalid credentials supplied
                raise InvalidCredentialsError('HTTP 401 Unauthorized returned: Invalid credentials supplied')
        elif auth == AuthMethod.SESSION:
            data = dict()
            data['UserName'] = self.__username
            data['Password'] = self.__password

            headers = dict()
            resp = self._rest_request(self.login_url, method="POST",body=data,
                                      headers=headers, allow_redirects=False)

            LOGGER.info('Login returned code %s: %s', resp.status, resp.text)

            self.__session_key = resp.session_key
            self.__session_location = resp.session_location

            if not self.__session_key and resp.status not in [200, 201, 202, 204]:
                if resp.status == 401:
                    # Invalid credentials supplied
                    raise InvalidCredentialsError('HTTP 401 Unauthorized returned: Invalid credentials supplied')
                else:
                    # Other type of error during session creation
                    error_str = resp.text
                    try:
                        error_str = resp.dict["error"]["@Message.ExtendedInfo"][0]["Message"]
                    except:
                        try:
                            error_str = resp.dict["error"]["message"]
                        except:
                            pass
                    raise SessionCreationError('HTTP {}: Failed to created the session\n{}'.format(resp.status, error_str))
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
        self._session.close()

class HttpClient(RestClientBase):
    """A client for Rest"""
    def __init__(self, base_url, username=None, password=None,
                                default_prefix='/redfish/v1/',
                                sessionkey=None, capath=None,
                                cafile=None, timeout=None,
                                max_retry=None, proxies=None):
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
        :param proxies: Dictionary containing protocol to proxy URL mappings
        :type proxies: dict

        """
        super(HttpClient, self).__init__(base_url, username=username,
                            password=password, default_prefix=default_prefix,
                            sessionkey=sessionkey, capath=capath,
                            cafile=cafile, timeout=timeout,
                            max_retry=max_retry, proxies=proxies)

        try:
            self.login_url = self.root.Links.Sessions['@odata.id']
        except KeyError:
            # While the "Links/Sessions" property is required, we can fallback
            # on the URI hardened in 1.6.0 of the specification if not found
            LOGGER.debug('"Links/Sessions" not found in Service Root.')
            self.login_url = '/redfish/v1/SessionService/Sessions'

    def _rest_request(self, path='', method="GET", args=None, body=None,
                      headers=None, allow_redirects=True):
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
        :param allow_redirects: controls whether redirects are followed
        :type allow_redirects: bool
        :returns: returns a rest request

        """
        return super(HttpClient, self)._rest_request(path=path, method=method,
                                                     args=args, body=body,
                                                     headers=headers,
                                                     allow_redirects=allow_redirects)

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
                                max_retry=None, proxies=None):
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
    :param proxies: Dictionary containing protocol to proxy URL mappings
    :type proxies: dict
    :returns: a client object.

    """
    if "://" not in base_url:
        warnings.warn("Scheme not specified for '{}'; adding 'https://'".format(base_url))
        base_url = "https://" + base_url
    return HttpClient(base_url=base_url, username=username, password=password,
                        default_prefix=default_prefix, sessionkey=sessionkey,
                        capath=capath, cafile=cafile, timeout=timeout,
                        max_retry=max_retry, proxies=proxies)

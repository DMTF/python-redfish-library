###
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md
###

# -*- coding: utf-8 -*-
"""RIS implementation"""

#---------Imports---------

import sys
import six
import logging
import threading

from six.moves.queue import Queue
from six.moves.urllib.parse import \
        urlparse, urlencode, urlunparse
from collections import (OrderedDict)

import jsonpath_rw
import redfish.rest.v1

from redfish.ris.sharedtypes import Dictable

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class SessionExpiredRis(Exception):
    """Raised when session has expired"""
    pass

class RisMonolithMemberBase(Dictable):
    """RIS monolith member base class"""
    pass

class RisMonolithMember_v1_0_0(RisMonolithMemberBase):
    """Wrapper around RestResponse that adds the monolith data"""
    def __init__(self, restresp):
        self._resp = restresp
        self._patches = list()
        self._type = None
        self._typestring = '@odata.type'

    def _get_type(self):
        """Return type from monolith"""
        if self._typestring in self._resp.dict:
            return self._resp.dict[self._typestring]
        elif 'type' in self._resp.dict:
            return self._resp.dict['type']
        return None
    type = property(_get_type, None)

    def _get_maj_type(self):
        """Return maj type from monolith"""
        if self.type:
            return self.type[:-4]
        return None
    maj_type = property(_get_maj_type, None)

    def _get_resp(self):
        """Return resp from monolith"""
        return self._resp
    resp = property(_get_resp, None)

    def _get_patches(self):
        """Return patches from monolith"""
        return self._patches
    patches = property(_get_patches, None)

    def to_dict(self):
        """Convert monolith to dict"""
        result = OrderedDict()
        if self.type:
            result['Type'] = self.type

            if self.maj_type == 'Collection.1' and \
                                            'MemberType' in self._resp.dict:
                result['MemberType'] = self._resp.dict['MemberType']

            result['links'] = OrderedDict()
            result['links']['href'] = ''
            headers = dict()

            for header in self._resp.getheaders():
                headers[header[0]] = header[1]

            result['Headers'] = headers

            if 'etag' in headers:
                result['ETag'] = headers['etag']

            result['OriginalUri'] = self._resp.request.path
            result['Content'] = self._resp.dict
            result['Patches'] = self._patches

        return result

    def load_from_dict(self, src):
        """Load variables from dict monolith"""
        """
        
        :param src: source to load from
        :type src: dict
        
        """
        if 'Type' in src:
            self._type = src['Type']
            restreq = redfish.rest.v1.RestRequest(method='GET', \
                                                    path=src['OriginalUri'])

            src['restreq'] = restreq
            self._resp = redfish.rest.v1.StaticRestResponse(**src)
            self._patches = src['Patches']

    def _reducer(self, indict, breadcrumbs=None, outdict=OrderedDict()):
        """Monolith reducer

        :param indict: input dictionary.
        :type indict: dict.
        :param breadcrumbs: breadcrumbs from previous operations.
        :type breadcrumbs: dict.
        :param outdict: expected output format.
        :type outdict: dictionary type.
        :returns: returns outdict

        """
        if breadcrumbs is None:
            breadcrumbs = []

        if isinstance(indict, dict):
            for key, val in list(indict.items()):
                breadcrumbs.append(key) # push

                if isinstance(val, dict):
                    self._reducer(val, breadcrumbs, outdict)
                elif isinstance(val, list) or isinstance(val, tuple):
                    for i in range(0, len(val)):
                        breadcrumbs.append('%s' % i) # push
                        self._reducer(val[i], breadcrumbs, outdict)

                        del breadcrumbs[-1] # pop
                elif isinstance(val, tuple):
                    self._reducer(val, breadcrumbs, outdict)
                else:
                    self._reducer(val, breadcrumbs, outdict)

                del breadcrumbs[-1] # pop
        else:
            outkey = '/'.join(breadcrumbs)
            outdict[outkey] = indict

        return outdict

    def _jsonpath_reducer(self, indict, breadcrumbs=None, \
                                                        outdict=OrderedDict()):
        """JSON Path Reducer

        :param indict: input dictionary.
        :type indict: dict.
        :param breadcrumbs: breadcrumbs from previous operations.
        :type breadcrumbs: dict.
        :param outdict: expected output format.
        :type outdict: dictionary type.
        :returns: returns outdict

        """
        if breadcrumbs is None:
            breadcrumbs = []

        if isinstance(indict, dict):
            for key, val in list(indict.items()):
                breadcrumbs.append(key) # push

                if isinstance(val, dict):
                    self._reducer(val, breadcrumbs, outdict)
                elif isinstance(val, list) or isinstance(val, tuple):
                    for i in range(0, len(val)):
                        breadcrumbs.append('[%s]' % i) # push
                        self._reducer(val[i], breadcrumbs, outdict)

                        del breadcrumbs[-1] # pop
                elif isinstance(val, tuple):
                    self._reducer(val, breadcrumbs, outdict)
                else:
                    self._reducer(val, breadcrumbs, outdict)

                del breadcrumbs[-1] # pop
        else:
            outkey = '.'.join(breadcrumbs)
            outkey = outkey.replace('.[', '[')
            outdict[outkey] = indict

        return outdict

    def reduce(self):
        """Returns a "flatten" dict with nested data represented in"""
        """ JSONpath notation"""
        result = OrderedDict()

        if self.type:
            result['Type'] = self.type

            if self.maj_type == 'Collection.1' and \
                                            'MemberType' in self._resp.dict:
                result['MemberType'] = self._resp.dict['MemberType']

            self._reducer(self._resp.dict)
            result['OriginalUri'] = self._resp.request.path
            result['Content'] = self._reducer(self._resp.dict)

        return result

class RisMonolith_v1_0_0(Dictable):
    """Monolithic cache of RIS data"""
    def __init__(self, client):
        """Initialize RisMonolith

        :param client: client to utilize
        :type client: RmcClient object

        """
        self._client = client
        self.name = "Monolithic output of RIS Service"
        self.types = OrderedDict()
        self._visited_urls = list()
        self._current_location = '/' # "root"
        self.queue = Queue()
        self._type = None
        self._name = None
        self.progress = 0
        self.reload = False

        self._typestring = '@odata.type'
        self._hrefstring = '@odata.id'

    def _get_type(self):
        """Return monolith version type"""
        return "Monolith.1.0.0"

    type = property(_get_type, None)

    def update_progress(self):
        """Simple function to increment the dot progress"""
        if self.progress % 6 == 0:
            sys.stdout.write('.')

    def get_visited_urls(self):
        """Return the visited URLS"""
        return self._visited_urls

    def set_visited_urls(self, visited_urls):
        """Set visited URLS to given list."""
        self._visited_urls = visited_urls

    def load(self, path=None, includelogs=False, skipinit=False, \
                        skipcrawl=False, loadtype='href', loadcomplete=False):
        """Walk entire RIS model and cache all responses in self.

        :param path: path to start load from.
        :type path: str.
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: boolean.
        :param skipinit: flag to determine if first run of load.
        :type skipinit: boolean.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: boolean

        """
        if not skipinit:
            if LOGGER.getEffectiveLevel() == 40:
                sys.stdout.write("Discovering data...")
            else:
                LOGGER.info("Discovering data...")
            self.name = self.name + ' at %s' % self._client.base_url

            if not self.types:
                self.types = OrderedDict()

        if not threading.active_count() >= 6:
            for _ in range(5):
                workhand = SuperDuperWorker(self.queue)
                workhand.setDaemon(True)
                workhand.start()

        selectivepath = path
        if not selectivepath:
            selectivepath = self._client._rest_client.default_prefix

        self._load(selectivepath, skipcrawl=skipcrawl, includelogs=includelogs,\
             skipinit=skipinit, loadtype=loadtype, loadcomplete=loadcomplete)
        self.queue.join()

        if not skipinit:
            if LOGGER.getEffectiveLevel() == 40:
                sys.stdout.write("Done\n")
            else:
                LOGGER.info("Done\n")

    def _load(self, path, skipcrawl=False, originaluri=None, includelogs=False,\
                        skipinit=False, loadtype='href', loadcomplete=False):
        """Helper function to main load function.

        :param path: path to start load from.
        :type path: str.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param originaluri: variable to assist in determining originating path.
        :type originaluri: str.
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: boolean.
        :param skipinit: flag to determine if first run of load.
        :type skipinit: boolean.
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: boolean

        """
        if path.endswith("?page=1"):
            return
        elif not includelogs:
            if "/Logs/" in path:
                return

        #TODO: need to find a better way to support non ascii characters
        path = path.replace("|", "%7C")

        #remove fragments
        newpath = urlparse(path)
        newpath = list(newpath[:])
        newpath[-1] = ''

        path = urlunparse(tuple(newpath))

        LOGGER.debug('_loading %s', path)

        if not self.reload:
            if path.lower() in self._visited_urls:
                return

        resp = self._client.get(path)

        if resp.status != 200:
            path = path + '/'
            resp = self._client.get(path)

            if resp.status == 401:
                raise SessionExpiredRis("Invalid session. Please logout and "\
                                        "log back in or include credentials.")
            elif resp.status != 200:
                return

        self.queue.put((resp, path, skipinit, self))

        if loadtype == 'href':
            #follow all the href attributes
            jsonpath_expr = jsonpath_rw.parse("$..'@odata.id'")
            matches = jsonpath_expr.find(resp.dict)

            if 'links' in resp.dict and 'NextPage' in resp.dict['links']:
                if originaluri:
                    next_link_uri = originaluri + '?page=' + \
                                    str(resp.dict['links']['NextPage']['page'])
                    href = '%s' % next_link_uri

                    self._load(href, originaluri=originaluri, \
                               includelogs=includelogs, skipcrawl=skipcrawl, \
                               skipinit=skipinit)
                else:
                    next_link_uri = path + '?page=' + \
                                    str(resp.dict['links']['NextPage']['page'])

                    href = '%s' % next_link_uri
                    self._load(href, originaluri=path, includelogs=includelogs,\
                                        skipcrawl=skipcrawl, skipinit=skipinit)

            if not skipcrawl:
                for match in matches:
                    if str(match.full_path) == "Registries.@odata.id" or \
                            str(match.full_path) == "JsonSchemas.@odata.id":
                        continue

                    if match.value == path:
                        continue

                    href = '%s' % match.value
                    self._load(href, skipcrawl=skipcrawl, \
                           originaluri=originaluri, includelogs=includelogs, \
                           skipinit=skipinit)

            if loadcomplete:
                for match in matches:
                    self._load(match.value, skipcrawl=skipcrawl, originaluri=\
                       originaluri, includelogs=includelogs, skipinit=skipinit)

    def branch_worker(self, resp, path, skipinit):
        """Helper for load function, creates threaded worker

        :param resp: response received.
        :type resp: str.
        :param path: path correlating to the response.
        :type path: str.
        :param skipinit: flag to determine if progress bar should be updated.
        :type skipinit: boolean.

        """
        self._visited_urls.append(path.lower())

        member = RisMonolithMember_v1_0_0(resp)
        if not member.type:
            return

        self.update_member(member)

        if not skipinit:
            self.progress += 1
            if LOGGER.getEffectiveLevel() == 40:
                self.update_progress()

    def update_member(self, member):
        """Adds member to this monolith. If the member already exists the"""
        """ data is updated in place.

        :param member: Ris monolith member object made by branch worker.
        :type member: RisMonolithMember_v1_0_0.

        """
        if member.maj_type not in self.types:
            self.types[member.maj_type] = OrderedDict()
            self.types[member.maj_type]['Instances'] = list()

        found = False

        for indices in range(len(self.types[member.maj_type]['Instances'])):
            inst = self.types[member.maj_type]['Instances'][indices]

            if inst.resp.request.path == member.resp.request.path:
                self.types[member.maj_type]['Instances'][indices] = member
                self.types[member.maj_type]['Instances'][indices].patches.\
                                    extend([patch for patch in inst.patches])

                found = True
                break

        if not found:
            self.types[member.maj_type]['Instances'].append(member)

    def load_from_dict(self, src):
        """Load data to monolith from dict

        :param src: data receive from rest operation.
        :type src: str.

        """
        self._type = src['Type']
        self._name = src['Name']
        self.types = OrderedDict()

        for typ in src['Types']:
            for inst in typ['Instances']:
                member = RisMonolithMember_v1_0_0(None)
                member.load_from_dict(inst)
                self.update_member(member)

        return

    def to_dict(self):
        """Convert data to monolith from dict"""
        result = OrderedDict()
        result['Type'] = self.type
        result['Name'] = self.name
        types_list = list()

        for typ in list(self.types.keys()):
            type_entry = OrderedDict()
            type_entry['Type'] = typ
            type_entry['Instances'] = list()

            for inst in self.types[typ]['Instances']:
                type_entry['Instances'].append(inst.to_dict())

            types_list.append(type_entry)

        result['Types'] = types_list
        return result

    def reduce(self):
        """Reduce monolith data"""
        result = OrderedDict()
        result['Type'] = self.type
        result['Name'] = self.name
        types_list = list()

        for typ in list(self.types.keys()):
            type_entry = OrderedDict()
            type_entry['Type'] = typ

            for inst in self.types[typ]['Instances']:
                type_entry['Instances'] = inst.reduce()

            types_list.append(type_entry)

        result['Types'] = types_list
        return result

    def _jsonpath2jsonpointer(self, instr):
        """Convert json path to json pointer

        :param instr: input path to be converted to pointer.
        :type instr: str.

        """
        outstr = instr.replace('.[', '[')
        outstr = outstr.replace('[', '/')
        outstr = outstr.replace(']', '/')

        if outstr.endswith('/'):
            outstr = outstr[:-1]

        return outstr

    def _get_current_location(self):
        """Return current location"""
        return self._current_location

    def _set_current_location(self, newval):
        """Set current location"""
        self._current_location = newval

    location = property(_get_current_location, _set_current_location)

    def list(self, lspath=None):
        """Function for list command

        :param lspath: path list.
        :type lspath: list.

        """
        results = list()
        path_parts = ['Types'] # Types is always assumed

        if isinstance(lspath, list) and len(lspath) > 0:
            lspath = lspath[0]
            path_parts.extend(lspath.split('/'))
        elif not lspath:
            lspath = '/'
        else:
            path_parts.extend(lspath.split('/'))

        currpos = self.to_dict()
        for path_part in path_parts:
            if not path_part:
                continue

            if isinstance(currpos, RisMonolithMember_v1_0_0):
                break
            elif isinstance(currpos, dict) and path_part in currpos:
                currpos = currpos[path_part]
            elif isinstance(currpos, list):
                for positem in currpos:
                    if 'Type' in positem and path_part == positem['Type']:
                        currpos = positem
                        break

        results.append(currpos)

        return results

    def killthreads(self):
        """Function to kill threads on logout"""
        threads = []
        for thread in threading.enumerate():
            if isinstance(thread, SuperDuperWorker):
                self.queue.put(('KILL', 'KILL', 'KILL', 'KILL'))
                threads.append(thread)

        for thread in threads:
            thread.join()

class RisMonolith(RisMonolith_v1_0_0):
    """Latest implementation of RisMonolith"""
    def __init__(self, client):
        """Initialize Latest RisMonolith

        :param client: client to utilize
        :type client: RmcClient object       

        """
        super(RisMonolith, self).__init__(client)

class SuperDuperWorker(threading.Thread):
    """Recursive worker implementation"""
    def __init__(self, queue):
        """Initialize SuperDuperWorker

        :param queue: queue for worker
        :type queue: Queue object       

        """
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        """Thread creator"""
        while True:
            (resp, path, skipinit, thobj) = self.queue.get()
            if resp == 'KILL' and path == 'KILL' and skipinit == 'KILL' and\
                                                            thobj == 'KILL':
                break
            thobj.branch_worker(resp, path, skipinit)
            self.queue.task_done()


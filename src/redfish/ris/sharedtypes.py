###
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md
###

# -*- coding: utf-8 -*-
""" Shared types used in this module """

#---------Imports---------

import logging
import jsonpatch
from redfish.rest.v1 import JSONEncoder

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class JSONEncoder(JSONEncoder):
    """Custom JSONEncoder that understands our types"""
    def default(self, obj):
        """Set defaults

		:param obj: json object.
        :type obj: str.

		"""
        if isinstance(obj, Dictable):
            return obj.to_dict()
        elif isinstance(obj, jsonpatch.JsonPatch):
            return obj.patch
        return super(JSONEncoder, self).default(obj)

class Dictable(object):
    """A base class which adds the to_dict method used during json encoding"""
    def to_dict(self):
        """Overridable funciton"""
        raise RuntimeError("You must override this method in your derived" \
                                                                    " class")


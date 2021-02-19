# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

# -*- coding: utf-8 -*-
"""Module for working with global configuration options."""

#---------Imports---------

import os
import re
import logging
import configparser

#---------End of imports---------


#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class AutoConfigParser(object):
    """Auto configuration parser"""
    # properties starting with _ac__ are automatically
    # serialized to config file
    _config_pattern = re.compile(r'_ac__(?P<confkey>.*)')

    def __init__(self, filename=None):
        """Initialize AutoConfigParser

        :param filename: file name to be used for config loading.
        :type filename: str.

        """
        self._sectionname = 'globals'
        self._configfile = filename

    def _get_ac_keys(self):
        """Retrieve parse option keys"""
        result = []
        for key in self.__dict__:
            match = AutoConfigParser._config_pattern.search(key)
            if match:
                result.append(match.group('confkey'))
        return result

    def _get(self, key):
        """Retrieve parse option key

        :param key: key to retrieve.
        :type key: str.

        """
        ackey = '_ac__%s' % key.replace('-', '_')
        if ackey in self.__dict__:
            return self.__dict__[ackey]
        return None

    def _set(self, key, value):
        """Set parse option key

        :param key: key to be set.
        :type key: str.
        :param value: value to be given to key.
        :type value: str.

        """
        ackey = '_ac__%s' % key.replace('-', '_')
        if ackey in self.__dict__:
            self.__dict__[ackey] = value
        return None

    def load(self, filename=None):
        """Load configuration settings from the file filename, if filename"""
        """ is None then the value from get_configfile() is used

        :param filename: file name to be used for config loading.
        :type filename: str.

        """
        fname = self.get_configfile()
        if filename is not None and len(filename) > 0:
            fname = filename

        if fname is None or not os.path.isfile(fname):
            return

        try:
            config = configparser.RawConfigParser()
            config.read(fname)
            for key in self._get_ac_keys():
                configval = None
                try:
                    configval = config.get(self._sectionname, key)
                except configparser.NoOptionError:
                    # also try with - instead of _
                    try:
                        configval = config.get(self._sectionname,
                                                        key.replace('_', '-'))
                    except configparser.NoOptionError:
                        pass

                if configval is not None and len(configval) > 0:
                    ackey = '_ac__%s' % key
                    self.__dict__[ackey] = configval
        except configparser.NoOptionError:
            pass
        except configparser.NoSectionError:
            pass

    def save(self, filename=None):
        """Save configuration settings from the file filename, if filename"""
        """ is None then the value from get_configfile() is used

        :param filename: file name to be used for config saving.
        :type filename: str.

        """
        fname = self.get_configfile()
        if filename is not None and len(filename) > 0:
            fname = filename

        if fname is None or len(fname) == 0:
            return

        config = configparser.RawConfigParser()
        try:
            config.add_section(self._sectionname)
        except configparser.DuplicateSectionError:
            pass # ignored

        for key in self._get_ac_keys():
            ackey = '_ac__%s' % key
            config.set(self._sectionname, key, str(self.__dict__[ackey]))

        fileh = open(self._configfile, 'w')
        config.write(fileh)
        fileh.close()

    def get_configfile(self):
        """ The current configuration file location"""
        return self._configfile


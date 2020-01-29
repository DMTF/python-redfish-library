# Copyright Notice:
# Copyright 2020 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#     https://github.com/DMTF/Redfish-Protocol-Validator/blob/master/LICENSE.md

import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from redfish.ris import rmc_helper


class RmcHelper(unittest.TestCase):
    def setUp(self):
        super(RmcHelper, self).setUp()

    @mock.patch('redfish.rest.v1.HttpClient')
    def test_get_cache_dirname(self, mock_http_client):
        url = 'http://example.com'
        helper = rmc_helper.RmcClient(url=url, username='oper', password='xyz')
        mock_http_client.return_value.get_base_url.return_value = url
        dir_name = helper.get_cache_dirname()
        self.assertEqual(dir_name, 'example.com/')


if __name__ == '__main__':
    unittest.main()

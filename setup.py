# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(name='redfish',
      version='3.0.3',
      description='Redfish Python Library',
      long_description=long_description,
      long_description_content_type='text/x-rst',
      author = 'DMTF, https://www.dmtf.org/standards/feedback',
      license='BSD 3-clause "New" or "Revised License"',
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 3',
          'Topic :: Communications'
      ],
      keywords='Redfish',
      url='https://github.com/DMTF/python-redfish-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpath_rw',
          'jsonpointer',
          'requests_toolbelt',
      ],
      extras_require={
          ':python_version == "3.4"': [
              'jsonpatch<=1.24'
          ],
          ':python_version >= "3.5"': [
              'jsonpatch'
          ]
      })

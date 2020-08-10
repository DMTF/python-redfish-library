from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(name='redfish',
      version='2.1.8',
      description='Redfish Python Library',
      long_description=long_description,
      long_description_content_type='text/x-rst',
      author = 'DMTF, https://www.dmtf.org/standards/feedback',
      license='BSD 3-clause "New" or "Revised License"',
      classifiers=[
          'Development Status :: 4 - Beta',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python',
          'Topic :: Communications'
      ],
      keywords='Redfish',
      url='https://github.com/DMTF/python-redfish-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpath_rw',
          'jsonpointer',
      ],
      extras_require={
          ':python_version == "3.4"': [
              'jsonpatch<=1.24'
          ],
          ':python_version >= "3.5" or python_version == "2.7"': [
              'jsonpatch'
          ]
      })

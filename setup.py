from setuptools import setup, find_packages

setup(name='redfish',
      version='2.0.1',
      description='Redfish Python Library',
      author = 'DMTF, https://www.dmtf.org/standards/feedback',
      license='BSD 3-clause "New" or "Revised License"',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python',
          'Topic :: Communications'
      ],
      keywords='Redfish',
      url='https://github.com/DMTF/python-redfish-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpatch',
          'jsonpath_rw',
          'jsonpointer',
          'urlparse2',
      ])

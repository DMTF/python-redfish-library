from setuptools import setup, find_packages

setup(name='redfish',
      version='1.0.0',
      description='Redsfish Python Library',
	  author = 'DMTF',
	  author_email = 'DMTF@DMTF.com',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
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

python-redfish-library
======================

.. image:: https://travis-ci.org/DMTF/python-redfish-library.svg?branch=master
    :target: https://travis-ci.org/DMTF/python-redfish-library
.. image:: https://img.shields.io/pypi/v/redfish.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/redfish
.. image:: https://img.shields.io/github/release/DMTF/python-redfish-library.svg?maxAge=2592000
    :target: https://github.com/DMTF/python-redfish-library/releases
.. image:: https://img.shields.io/badge/License-BSD%203--Clause-blue.svg
    :target: https://raw.githubusercontent.com/DMTF/python-redfish-library/master/LICENSE
.. image:: https://img.shields.io/pypi/pyversions/redfish.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/redfish
.. image:: https://api.codacy.com/project/badge/Grade/1283adc3972d42b4a3ddb9b96660bc07
    :target: https://www.codacy.com/app/rexysmydog/python-redfish-library?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=DMTF/python-redfish-library&amp;utm_campaign=Badge_Grade


.. contents:: :depth: 1


Description
-----------

As of version 3.0.0, Python2 is no longer supported.  If Python2 is required, ``redfish<3.0.0`` can be specified in a requirements file.

REST (Representational State Transfer) is a web based software architectural style consisting of a set of constraints that focuses on a system's resources. The Redfish library performs the basic HTTPS operations GET, POST, PUT, PATCH and DELETE on resources using the HATEOAS (Hypermedia as the Engine of Application State) Redfish architecture. API clients allow you to manage and interact with the system through a fixed URL and several URIs. Go to the `wiki <../../wiki>`_ for more details.


Installing
----------

.. code-block:: console

    pip install redfish


Building from zip file source
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

    python setup.py sdist --formats=zip (this will produce a .zip file)
    cd dist
    pip install redfish-x.x.x.zip


Requirements
------------

Ensure the system does not have the OpenStack "python-redfish" module installed on the target system.  This module is using a conflicting package name that this library already uses.  The module in question can be found here: https://pypi.org/project/python-redfish/


Usage
----------

A set of examples is provided under the examples directory of this project. In addition to the directives present in this paragraph, you will find valuable implementation tips and tricks in those examples.


Import the relevant python module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a Redfish compliant application import the relevant python module.

For Redfish compliant application:

.. code-block:: python

    import redfish


Create a Redfish Object
~~~~~~~~~~~~~~~~~~~~~~~

The Redfish Objects contain 3 parameters: the target secured URL (i.e. "https://IP" or "https://X.Y.Z.T"), an user name and its password.
There are additional 2 optional parameters: timeout (in seconds before a connection initialization times out) and max_retry (how many times a request will retry after a timeout). If unset these default to None and 10 respectively.
To crete a Redfish Object, call the redfish_client method:

.. code-block:: python

    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, \
                          password=login_password, default_prefix='/redfish/v1')


Login to the server
~~~~~~~~~~~~~~~~~~~

The login operation is performed when creating the REDFISH_OBJ. You can continue with a basic authentication, but it would less secure.

.. code-block:: python

    REDFISH_OBJ.login(auth="session")


Perform a GET operation
~~~~~~~~~~~~~~~~~~~~~~~

A simple GET operation can be performed to obtain the data present in any valid path.
An example of rawget operation on the path "/redfish/v1/systems/1" is shown below:

.. code-block:: python

    response = REDFISH_OBJ.get("/redfish/v1/systems/1", None)


Perform a POST operation
~~~~~~~~~~~~~~~~~~~~~~~~

A POST operation can be performed to create a resource or perform an action.
An example of a POST operation on the path "/redfish/v1/systems/1/Actions/ComputerSystem.Reset" is shown below:

.. code-block:: python

    body = {"ResetType": "GracefulShutdown"}
    response = REDFISH_OBJ.post("/redfish/v1/systems/1/Actions/ComputerSystem.Reset", body=body)


Working with Tasks
~~~~~~~~~~~~~~~~~~

A POST operation may result in a task, describing an operation with a duration greater than the span of a single request.
The action message object that is_processing will return a Task resource that can be accessed reviewed when polled with monitor.
An example of a POST operation with a possible Task is shown below.

.. code-block:: python

    body = {"ResetType": "GracefulShutdown"}
    response = REDFISH_OBJ.post("/redfish/v1/systems/1/Actions/ComputerSystem.Reset", body=body)
    if(response.is_processing):
        task = response.monitor(context)

        while(task.is_processing):
            retry_time = task.retry_after
            task_status = task.dict['TaskState']
            time.sleep(retry_time if retry_time else 5)
            task = response.monitor(context)


Logout the created session
~~~~~~~~~~~~~~~~~~~~~~~~~~

Make sure you logout every session you create as it will remain alive until it times out.

.. code-block:: python

    REDFISH_OBJ.logout()


A logout deletes the current sesssion from the system. The redfish_client object destructor includes a logout statement.

Using proxies
~~~~~~~~~~~~~

You can use a proxy by specifying the ``HTTP_PROXY`` and ``HTTPS_PROXY`` environment variables.  Hosts to be excluded from the proxy can be specified using the NO_PROXY environment variable.

.. code-block:: shell

    export HTTP_PROXY="http://192.168.1.10:8888"
    export HTTPS_PROXY="http://192.168.1.10:8888"

Contributing
------------

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D


Release Process
---------------

Run the `release.sh` script to publish a new version.

.. code-block:: shell

    sh release.sh <NewVersion>


Enter the release notes when prompted; an empty line signifies no more notes to add.

Copyright and License
---------------------

Copyright Notice:
Copyright 2016-2021 DMTF. All rights reserved.
License: BSD 3-Clause License. For full text see link: `https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md <https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md>`_

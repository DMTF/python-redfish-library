python-redfish-library
======================

.. image:: https://img.shields.io/pypi/v/redfish.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/redfish
.. image:: https://img.shields.io/github/release/DMTF/python-redfish-library.svg?maxAge=2592000
    :target: https://github.com/DMTF/python-redfish-library/releases
.. image:: https://img.shields.io/badge/License-BSD%203--Clause-blue.svg
    :target: https://raw.githubusercontent.com/DMTF/python-redfish-library/master/LICENSE
.. image:: https://img.shields.io/pypi/pyversions/redfish.svg?maxAge=2592000
    :target: https://pypi.python.org/pypi/redfish

.. contents:: :depth: 1

Description
-----------

As of version 3.0.0, Python2 is no longer supported.  If Python2 is required, ``redfish<3.0.0`` can be specified in a requirements file.

REST (Representational State Transfer) is a web based software architectural style consisting of a set of constraints that focuses on a system's resources.  The Redfish library performs GET, POST, PUT, PATCH and DELETE HTTP operations on resources within a Redfish service.  Go to the `wiki <../../wiki>`_ for more details.

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

A set of examples is provided under the examples directory of this project.  In addition to the directives present in this paragraph, you will find valuable implementation tips and tricks in those examples.

Import the relevant Python module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a Redfish conformant application import the relevant Python module.

For Redfish conformant application:

.. code-block:: python

    import redfish

Create a Redfish object
~~~~~~~~~~~~~~~~~~~~~~~

The Redfish object contains three required parameters:

* ``base_url``: The address of the Redfish service (with scheme).  Example: ``https://192.168.1.100``.  For Unix sockets, use the scheme ``http+unix://``, followed by the percent-encoded filepath to the socket.
* ``username``: The username for authentication.
* ``password``: The password for authentication.

There are several optional parameters:

* ``default_prefix``: The path to the Redfish service root.  This is only used for initial connection and authentication with the service.  The default value is ``/redfish/v1/``.
* ``sessionkey``: The session key to use with subsequent requests.  This can be used to bypass the login step.  The default value is ``None``.
* ``cafile``: The file path to the CA certificate that issued the Redfish service's certificate.  The default value is ``None``.
* ``timeout``: The number of seconds to wait for a response before closing the connection.  The default value is ``None``.
* ``max_retry``: The number of retries to perform an operation before giving up.  The default value is ``10``.
* ``proxies``: A dictionary containing protocol to proxy URL mappings.  The default value is ``None``.  See `Using proxies`_.

To crete a Redfish object, call the ``redfish_client`` method:

.. code-block:: python

    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, \
                          password=login_password, default_prefix='/redfish/v1/')

Login to the service
~~~~~~~~~~~~~~~~~~~~

After creating the REDFISH_OBJ, perform the ``login`` operation to authenticate with the service.  The ``auth`` parameter allows you to specify the login method.  Possible values are:

* ``session``: Creates a Redfish session with a session token.
* ``basic``: Uses HTTP Basic authentication for all requests.

.. code-block:: python

    REDFISH_OBJ.login(auth="session")

Perform a GET operation
~~~~~~~~~~~~~~~~~~~~~~~

A simple GET operation can be performed to obtain the data present in any valid path.
An example of GET operation on the path "/redfish/v1/systems/1" is shown below:

.. code-block:: python

    response = REDFISH_OBJ.get("/redfish/v1/systems/1", None)

Perform a POST operation
~~~~~~~~~~~~~~~~~~~~~~~~

A POST operation can be performed to create a resource or perform an action.
An example of a POST operation on the path "/redfish/v1/systems/1/Actions/ComputerSystem.Reset" is shown below:

.. code-block:: python

    body = {"ResetType": "GracefulShutdown"}
    response = REDFISH_OBJ.post("/redfish/v1/systems/1/Actions/ComputerSystem.Reset", body=body)

Working with tasks
~~~~~~~~~~~~~~~~~~

A POST and PATCH operations may result in a task, describing an operation with a duration greater than the span of a single request.
The action message object that ``is_processing`` will return a task that can be accessed reviewed when polled with monitor.
An example of a POST operation with a possible task is shown below.

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

Ensure you perform a ``logout`` operation when done interacting with the Redfish service.  If this step isn't performed, the session will remain active until the Redfish service decides to close it.

.. code-block:: python

    REDFISH_OBJ.logout()

The ``logout`` operation deletes the current sesssion from the service.  The ``redfish_client`` object destructor includes a logout statement.

Using proxies
~~~~~~~~~~~~~

There are two methods for using proxies: configuring environment variables or directly providing proxy information.

Environment variables
^^^^^^^^^^^^^^^^^^^^^

You can use a proxy by specifying the ``HTTP_PROXY`` and ``HTTPS_PROXY`` environment variables.  Hosts to be excluded from the proxy can be specified using the NO_PROXY environment variable.

.. code-block:: shell

    export HTTP_PROXY="http://192.168.1.10:8888"
    export HTTPS_PROXY="http://192.168.1.10:8888"

Directly provided
^^^^^^^^^^^^^^^^^

You can use a proxy by building a dictionary containing the proxy information and providing it to the ``proxies`` argument when creating the ``redfish_client`` object.
The key-value pairs of the dictionary contain the protocol and the proxy URL for the protocol.

.. code-block:: python

    proxies = {
        'http': 'http://192.168.1.10:8888',
        'https': 'http://192.168.1.10:8888',
    }
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, \
                          password=login_password, proxies=proxies)

SOCKS proxy support
^^^^^^^^^^^^^^^^^^^

An additional package is required to use SOCKS proxies.

.. code-block:: console

    pip install -U requests[socks]

Once installed, the proxy can be configured using environment variables or directly provided like any other proxy.
For example:

.. code-block:: shell

    export HTTP_PROXY="socks5h://localhost:8123"
    export HTTPS_PROXY="socks5h://localhost:8123"

Release Process
---------------

1. Go to the "Actions" page
2. Select the "Release and Publish" workflow
3. Click "Run workflow"
4. Fill out the form
5. Click "Run workflow"

Copyright and License
---------------------

Copyright Notice:
Copyright 2016-2022 DMTF. All rights reserved.
License: BSD 3-Clause License. For full text see link: `https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md <https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md>`_

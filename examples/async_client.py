# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Retrieve the service root with the asynchronous Redfish client."""

import asyncio
import os

import aiohttp

from redfish.aio import AsyncRedfishClient


async def main():
    """Retrieve and display the Redfish service root."""
    async with aiohttp.ClientSession() as session:
        async with AsyncRedfishClient(
            base_url=os.environ["REDFISH_BASE_URL"],
            username=os.environ["REDFISH_USERNAME"],
            password=os.environ["REDFISH_PASSWORD"],
            session=session,
            timeout=10,
        ) as client:
            service_root = await client.get_service_root()
            print(service_root)


if __name__ == "__main__":
    asyncio.run(main())

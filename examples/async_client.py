# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Discover ComputerSystem resources with the asynchronous Redfish client."""

import asyncio
import os

import aiohttp

from redfish.aio import AsyncRedfishClient


async def main():
    """Discover and display Redfish ComputerSystem resources."""
    async with aiohttp.ClientSession() as session:
        async with AsyncRedfishClient(
            base_url=os.environ["REDFISH_BASE_URL"],
            username=os.environ["REDFISH_USERNAME"],
            password=os.environ["REDFISH_PASSWORD"],
            session=session,
            timeout=10,
        ) as client:
            systems = await client.get_systems()
            for system in systems.values():
                print(
                    "{}: power={}, reset_types={}".format(
                        system.name or system.system_id,
                        system.power_state,
                        sorted(system.reset_types),
                    )
                )


if __name__ == "__main__":
    asyncio.run(main())

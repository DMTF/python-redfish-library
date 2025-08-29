#!/usr/bin/env python3
import argparse
from pathlib import Path
from typing import Optional
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from redfish import redfish_client


def make_dhe_compatible_context(
    cafile: Optional[Path] = None,
    *,
    seclevel: int = 1,
    verify: bool = True,
    tls12_only: bool = True,
) -> ssl.SSLContext:
    """
    Build an SSLContext that accepts legacy DHE handshakes (small DH groups).
    - seclevel=1 usually permits 1024-bit DH. Use 0 only as a last resort.
    - If verify=True and the server is self-signed, pass its PEM as `cafile`.
    - DHE is TLS<=1.2; set tls12_only=True to pin TLS 1.2.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers(f"DEFAULT:@SECLEVEL={seclevel}:DHE")
    ctx.options |= ssl.OP_NO_COMPRESSION
    if tls12_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    if verify:
        if cafile:
            ctx.load_verify_locations(str(cafile))
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

class SSLContextAdapter(HTTPAdapter):
    """requests adapter that injects a custom ssl_context into urllib3."""
    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_context
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


# Test dhe adapter
ctx = make_dhe_compatible_context(seclevel=0, verify=False)
adapter = SSLContextAdapter(ctx)
parser = argparse.ArgumentParser( )
parser.add_argument('url',help="Server with DHE encryption")
args = parser.parse_args()

client = redfish_client(args.url,https_adapter=adapter)



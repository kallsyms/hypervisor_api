#!/usr/bin/env python3
import logging
import pypureomapi

from .classes import IPResolver
from .exceptions import MACNotResolvedException


class OMAPIResolver(IPResolver):
    """
    A resolver class for DHCP servers exposing an OMAPI control port (basically ISC DHCPd)
    """
    def __init__(
            self,
            host: str,
            key: str,
            secret: str,
            port: int = 7911):
        self.logger = logging.getLogger(__name__)
        self.omapi = pypureomapi.Omapi(host, port, key, secret)
        self.logger.debug("Successfully connected to OMAPI server at %s:%d", host, port)

    def get_ip(self, mac: str):
        try:
            return self.omapi.lookup_ip(mac)
        except pypureomapi.OmapiErrorNotFound:
            return MACNotResolvedException()

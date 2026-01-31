"""Impacket SAMRDump - Enumerate SAM users and groups via MSRPC"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SAMRDump(_ImpacketModule):
    def __init__(self):
        super().__init__("samrdump")
        self.name = "impacket_samrdump"
        self.description = "Enumerate SAM users and groups via MSRPC"

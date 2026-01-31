"""Impacket LookupSID - SID brute-force to enumerate users and groups"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class LookupSID(_ImpacketModule):
    def __init__(self):
        super().__init__("lookupsid")
        self.name = "impacket_lookupsid"
        self.description = "SID brute-force to enumerate users and groups"

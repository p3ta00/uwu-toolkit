"""Impacket FindDelegation - Find delegation relationships in AD"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class FindDelegation(_ImpacketModule):
    def __init__(self):
        super().__init__("findDelegation")
        self.name = "impacket_findDelegation"
        self.description = "Find delegation relationships in AD"

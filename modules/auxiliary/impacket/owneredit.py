"""Impacket OwnerEdit - Edit object ownership in AD"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class OwnerEdit(_ImpacketModule):
    def __init__(self):
        super().__init__("owneredit")
        self.name = "impacket_owneredit"
        self.description = "Edit object ownership in AD"

"""Impacket GetST - Request a service ticket (TGS) given a TGT"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetST(_ImpacketModule):
    def __init__(self):
        super().__init__("getST")
        self.name = "impacket_getST"
        self.description = "Request a service ticket (TGS) given a TGT"

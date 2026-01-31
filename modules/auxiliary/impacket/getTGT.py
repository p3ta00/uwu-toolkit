"""Impacket GetTGT - Request a TGT ticket and save as ccache"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetTGT(_ImpacketModule):
    def __init__(self):
        super().__init__("getTGT")
        self.name = "impacket_getTGT"
        self.description = "Request a TGT ticket and save as ccache"

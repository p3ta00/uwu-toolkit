"""Impacket GetArch - Detect remote host architecture (32/64-bit)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetArch(_ImpacketModule):
    def __init__(self):
        super().__init__("getArch")
        self.name = "impacket_getArch"
        self.description = "Detect remote host architecture (32/64-bit)"

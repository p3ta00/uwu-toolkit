"""Impacket Reg - Remote Windows registry operations"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Reg(_ImpacketModule):
    def __init__(self):
        super().__init__("reg")
        self.name = "impacket_reg"
        self.description = "Remote Windows registry operations"

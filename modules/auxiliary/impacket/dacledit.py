"""Impacket DACLEdit - Edit DACLs on AD objects"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class DACLEdit(_ImpacketModule):
    def __init__(self):
        super().__init__("dacledit")
        self.name = "impacket_dacledit"
        self.description = "Edit DACLs on AD objects"

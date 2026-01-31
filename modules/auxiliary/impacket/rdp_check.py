"""Impacket RDPCheck - Check valid RDP credentials on target"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class RDPCheck(_ImpacketModule):
    def __init__(self):
        super().__init__("rdp_check")
        self.name = "impacket_rdp_check"
        self.description = "Check valid RDP credentials on target"

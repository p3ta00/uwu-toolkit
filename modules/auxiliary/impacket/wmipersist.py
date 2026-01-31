"""Impacket WMIPersist - WMI event subscription persistence"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class WMIPersist(_ImpacketModule):
    def __init__(self):
        super().__init__("wmipersist")
        self.name = "impacket_wmipersist"
        self.description = "WMI event subscription persistence"

"""Impacket Netview - Enumerate sessions and shares on remote hosts"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Netview(_ImpacketModule):
    def __init__(self):
        super().__init__("netview")
        self.name = "impacket_netview"
        self.description = "Enumerate sessions and shares on remote hosts"

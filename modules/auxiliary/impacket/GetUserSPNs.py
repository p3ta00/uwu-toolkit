"""Impacket GetUserSPNs - Kerberoasting - request SPN tickets for offline cracking"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetUserSPNs(_ImpacketModule):
    def __init__(self):
        super().__init__("GetUserSPNs")
        self.name = "impacket_GetUserSPNs"
        self.description = "Kerberoasting - request SPN tickets for offline cracking"

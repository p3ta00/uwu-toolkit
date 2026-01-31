"""Impacket GetADUsers - Enumerate Active Directory users via LDAP"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetADUsers(_ImpacketModule):
    def __init__(self):
        super().__init__("GetADUsers")
        self.name = "impacket_GetADUsers"
        self.description = "Enumerate Active Directory users via LDAP"

"""Impacket SecretsDump - Dump SAM/LSA/NTDS secrets remotely"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SecretsDump(_ImpacketModule):
    def __init__(self):
        super().__init__("secretsdump")
        self.name = "impacket_secretsdump"
        self.description = "Dump SAM/LSA/NTDS secrets remotely"

"""Impacket KarmaSMB - SMB server that auto-responds to any auth request"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class KarmaSMB(_ImpacketModule):
    def __init__(self):
        super().__init__("karmaSMB")
        self.name = "impacket_karmaSMB"
        self.description = "SMB server that auto-responds to any auth request"

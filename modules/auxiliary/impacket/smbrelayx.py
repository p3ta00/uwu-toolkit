"""Impacket SMBRelayx - SMB relay attack (simpler than ntlmrelayx)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SMBRelayx(_ImpacketModule):
    def __init__(self):
        super().__init__("smbrelayx")
        self.name = "impacket_smbrelayx"
        self.description = "SMB relay attack (simpler than ntlmrelayx)"

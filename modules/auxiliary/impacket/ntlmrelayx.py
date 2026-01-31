"""Impacket NTLMRelayx - NTLM relay attack tool (relay captured auth)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class NTLMRelayx(_ImpacketModule):
    def __init__(self):
        super().__init__("ntlmrelayx")
        self.name = "impacket_ntlmrelayx"
        self.description = "NTLM relay attack tool (relay captured auth)"

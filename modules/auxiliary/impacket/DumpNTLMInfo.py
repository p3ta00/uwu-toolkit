"""Impacket DumpNTLMInfo - Dump NTLM authentication info from target"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class DumpNTLMInfo(_ImpacketModule):
    def __init__(self):
        super().__init__("DumpNTLMInfo")
        self.name = "impacket_DumpNTLMInfo"
        self.description = "Dump NTLM authentication info from target"

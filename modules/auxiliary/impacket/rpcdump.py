"""Impacket RPCDump - Dump RPC endpoints on a target"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class RPCDump(_ImpacketModule):
    def __init__(self):
        super().__init__("rpcdump")
        self.name = "impacket_rpcdump"
        self.description = "Dump RPC endpoints on a target"

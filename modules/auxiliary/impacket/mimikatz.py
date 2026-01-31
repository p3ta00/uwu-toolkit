"""Impacket Mimikatz - Remote mimikatz execution via RPC"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Mimikatz(_ImpacketModule):
    def __init__(self):
        super().__init__("mimikatz")
        self.name = "impacket_mimikatz"
        self.description = "Remote mimikatz execution via RPC"

"""Impacket GetNPUsers - AS-REP Roast - extract hashes from no-preauth accounts"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetNPUsers(_ImpacketModule):
    def __init__(self):
        super().__init__("GetNPUsers")
        self.name = "impacket_GetNPUsers"
        self.description = "AS-REP Roast - extract hashes from no-preauth accounts"

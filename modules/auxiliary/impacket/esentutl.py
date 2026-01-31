"""Impacket Esentutl - Parse ESE database files (NTDS.dit, etc.)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Esentutl(_ImpacketModule):
    def __init__(self):
        super().__init__("esentutl")
        self.name = "impacket_esentutl"
        self.description = "Parse ESE database files (NTDS.dit, etc.)"

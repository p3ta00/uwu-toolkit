"""Impacket GoldenPac - MS14-068 exploit - forge Kerberos PAC for domain admin"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GoldenPac(_ImpacketModule):
    def __init__(self):
        super().__init__("goldenPac")
        self.name = "impacket_goldenPac"
        self.description = "MS14-068 exploit - forge Kerberos PAC for domain admin"

"""Impacket PSExec - Remote execution via RemComSvc (creates service)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class PSExec(_ImpacketModule):
    def __init__(self):
        super().__init__("psexec")
        self.name = "impacket_psexec"
        self.description = "Remote execution via RemComSvc (creates service)"

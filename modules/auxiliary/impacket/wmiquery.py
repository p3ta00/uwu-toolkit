"""Impacket WMIQuery - Execute WQL queries via WMI"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class WMIQuery(_ImpacketModule):
    def __init__(self):
        super().__init__("wmiquery")
        self.name = "impacket_wmiquery"
        self.description = "Execute WQL queries via WMI"

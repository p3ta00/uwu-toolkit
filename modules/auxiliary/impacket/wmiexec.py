"""Impacket WMIExec - Semi-interactive shell via WMI (stealthier)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class WMIExec(_ImpacketModule):
    def __init__(self):
        super().__init__("wmiexec")
        self.name = "impacket_wmiexec"
        self.description = "Semi-interactive shell via WMI (stealthier)"

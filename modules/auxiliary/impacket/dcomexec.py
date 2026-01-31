"""Impacket DCOMExec - Exec via DCOM (MMC20, ShellWindows, ShellBrowserWindow)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class DCOMExec(_ImpacketModule):
    def __init__(self):
        super().__init__("dcomexec")
        self.name = "impacket_dcomexec"
        self.description = "Exec via DCOM (MMC20, ShellWindows, ShellBrowserWindow)"

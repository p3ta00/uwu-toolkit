"""Impacket MSSQLClient - Interactive MSSQL client with command execution"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class MSSQLClient(_ImpacketModule):
    def __init__(self):
        super().__init__("mssqlclient")
        self.name = "impacket_mssqlclient"
        self.description = "Interactive MSSQL client with command execution"

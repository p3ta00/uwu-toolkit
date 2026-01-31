"""Impacket MSSQLInstance - Discover MSSQL instances via browser service"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class MSSQLInstance(_ImpacketModule):
    def __init__(self):
        super().__init__("mssqlinstance")
        self.name = "impacket_mssqlinstance"
        self.description = "Discover MSSQL instances via browser service"

"""Impacket RBCD - Resource-Based Constrained Delegation abuse"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class RBCD(_ImpacketModule):
    def __init__(self):
        super().__init__("rbcd")
        self.name = "impacket_rbcd"
        self.description = "Resource-Based Constrained Delegation abuse"

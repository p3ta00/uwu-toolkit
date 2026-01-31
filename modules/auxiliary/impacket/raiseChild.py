"""Impacket RaiseChild - Escalate from child to parent domain via trust"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class RaiseChild(_ImpacketModule):
    def __init__(self):
        super().__init__("raiseChild")
        self.name = "impacket_raiseChild"
        self.description = "Escalate from child to parent domain via trust"

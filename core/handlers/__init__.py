"""
Command handlers for UwU Toolkit console.
Each handler groups related commands and receives a reference to the console.
"""


class HandlerBase:
    """Base class for all command handlers."""

    def __init__(self, console: 'UwUConsole'):
        self.console = console

    @property
    def config(self):
        return self.console.config

    @property
    def loader(self):
        return self.console.loader

    @property
    def current_module(self):
        return self.console.current_module

    @current_module.setter
    def current_module(self, value):
        self.console.current_module = value


# Import handlers AFTER HandlerBase is defined to avoid circular imports
from .module_handler import ModuleHandler
from .variable_handler import VariableHandler
from .server_handler import ServerHandler
from .shell_handler import ShellHandler
from .c2_handler import C2Handler
from .tools_handler import ToolsHandler


__all__ = [
    'HandlerBase',
    'ModuleHandler',
    'VariableHandler',
    'ServerHandler',
    'ShellHandler',
    'C2Handler',
    'ToolsHandler',
]

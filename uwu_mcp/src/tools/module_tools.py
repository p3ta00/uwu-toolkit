"""MCP tools for UwU Toolkit module management."""

import io
import json
import os
import sys
from contextlib import redirect_stdout, redirect_stderr

from .common import _format_response, UWU_ROOT


def register(mcp):

    @mcp.tool()
    async def uwu_list_modules(
        search: str = "",
        module_type: str = "",
    ) -> str:
        """
        List available UwU Toolkit modules. Optionally search by name/tag.

        Args:
            search: Search query (matches name, description, tags)
            module_type: Filter by type (auxiliary, exploit, enumeration, post, payloads)
        """
        modules_path = os.path.join(UWU_ROOT, "modules")
        if not os.path.isdir(modules_path):
            return _format_response(error=f"Modules path not found: {modules_path}")

        try:
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)

            from core.module_loader import ModuleLoader
            loader = ModuleLoader(modules_path)
            discovered = loader.discover_modules()

            results = []
            for path, info in sorted(discovered.items()):
                # Apply search filter
                if search:
                    query = search.lower()
                    searchable = f"{info.name} {info.description} {' '.join(info.tags)} {info.path}".lower()
                    if query not in searchable:
                        continue
                # Apply type filter
                if module_type and info.module_type.value != module_type:
                    continue

                results.append({
                    "path": info.path,
                    "name": info.name,
                    "description": info.description,
                    "type": info.module_type.value,
                    "platform": str(info.platform),
                    "tags": info.tags,
                })

            return _format_response(
                data={"modules": results, "count": len(results)},
                message=f"Found {len(results)} modules"
            )
        except Exception as e:
            return _format_response(error=f"Failed to list modules: {e}")

    @mcp.tool()
    async def uwu_run_module(
        module_path: str,
        options: str = "{}",
    ) -> str:
        """
        Load and run a UwU Toolkit module with given options.

        Args:
            module_path: Module path (e.g., auxiliary/ad/kerberoast)
            options: JSON object of option name -> value pairs
        """
        modules_path = os.path.join(UWU_ROOT, "modules")
        try:
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)

            from core.module_loader import ModuleLoader
            from core.config import Config

            loader = ModuleLoader(modules_path)
            module = loader.load_module(module_path)
            if not module:
                return _format_response(error=f"Module not found: {module_path}")

            # Set up config
            config = Config()
            module.set_config(config)

            # Set options
            opts = json.loads(options) if isinstance(options, str) else options
            for name, value in opts.items():
                module.set_option(name.upper(), str(value))

            # Validate
            valid, missing = module.validate_options()
            if not valid:
                return _format_response(
                    error=f"Missing required options: {', '.join(missing)}"
                )

            # Capture output
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()

            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                success = module.run()

            output = stdout_buf.getvalue() + stderr_buf.getvalue()
            return _format_response(
                data={
                    "success": success,
                    "output": output,
                    "module": module_path,
                },
                success=success,
                message=f"Module {module_path} {'completed' if success else 'failed'}"
            )
        except Exception as e:
            return _format_response(error=f"Module execution error: {e}")

    @mcp.tool()
    async def uwu_module_info(module_path: str) -> str:
        """
        Get detailed information about a UwU Toolkit module including options.

        Args:
            module_path: Module path (e.g., auxiliary/ad/kerberoast)
        """
        modules_path = os.path.join(UWU_ROOT, "modules")
        try:
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)

            from core.module_loader import ModuleLoader
            loader = ModuleLoader(modules_path)
            module = loader.load_module(module_path)
            if not module:
                return _format_response(error=f"Module not found: {module_path}")

            options = {}
            for name, opt in module._options.items():
                options[name] = {
                    "description": opt.description,
                    "required": opt.required,
                    "default": opt.default,
                    "choices": opt.choices if opt.choices else None,
                    "value": opt.value,
                }

            info = {
                "name": module.name,
                "description": module.description,
                "author": module.author,
                "version": module.version,
                "type": module.module_type.value if module.module_type else "",
                "platform": module.platform.value if module.platform else "",
                "tags": module.tags,
                "references": module.references,
                "options": options,
            }
            return _format_response(data=info)
        except Exception as e:
            return _format_response(error=f"Failed to get module info: {e}")

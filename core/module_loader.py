"""
Module loader and manager for UwU Toolkit
Handles discovery, loading, and searching of modules
"""

import ast
import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from .module_base import ModuleBase, ModuleType


@dataclass
class ModuleInfo:
    """Lightweight module metadata (loaded without instantiating)"""
    path: str  # Full path like "impacket/psexec" or "ad/kerberoast"
    file_path: Path  # Actual file path
    name: str
    description: str
    module_type: ModuleType
    tags: List[str]
    platform: str
    author: str
    virtual_key: str = ""  # For registry-based virtual modules (e.g., "psexec")


class ModuleLoader:
    """Discovers, loads, and manages modules"""

    def __init__(self, modules_path: str):
        self.modules_path = Path(modules_path)
        self._module_cache: Dict[str, ModuleInfo] = {}
        self._loaded_modules: Dict[str, ModuleBase] = {}
        # Map old paths to new paths for backward compatibility
        self._path_aliases: Dict[str, str] = {}

    def discover_modules(self) -> Dict[str, ModuleInfo]:
        """
        Discover all available modules.

        Scans ModuleType directories (auxiliary/, exploits/, etc.) and
        any additional top-level directories (impacket/, bloodyad/, ad/).
        Also registers virtual modules from base class registries.

        Returns dict of module_path -> ModuleInfo
        """
        self._module_cache.clear()
        self._path_aliases.clear()

        type_dir_names = {mt.value for mt in ModuleType}

        # Phase 1: Scan ModuleType directories (auxiliary/, exploits/, etc.)
        for module_type in ModuleType:
            type_dir = self.modules_path / module_type.value
            if not type_dir.exists():
                type_dir.mkdir(parents=True, exist_ok=True)
                continue
            self._scan_directory(type_dir, module_type)

        # Phase 2: Scan additional top-level directories (impacket/, bloodyad/, ad/, etc.)
        for item in sorted(self.modules_path.iterdir()):
            if (item.is_dir() and
                not item.name.startswith(('_', '.')) and
                item.name not in type_dir_names):
                self._scan_directory(item, ModuleType.AUXILIARY, path_root=item.name)

        # Phase 3: Register virtual modules from base class registries
        self._register_virtual_modules()

        return self._module_cache

    def _scan_directory(
        self,
        directory: Path,
        module_type: ModuleType,
        prefix: str = "",
        path_root: str = "",
    ) -> None:
        """Recursively scan directory for modules.

        Args:
            directory: Directory to scan
            module_type: Module type for metadata
            prefix: Current subdirectory prefix within the scan
            path_root: Override for the root path segment (e.g., "impacket"
                       instead of module_type.value)
        """
        root = path_root if path_root else module_type.value

        for item in directory.iterdir():
            if item.name.startswith("_") or item.name.startswith("."):
                continue

            if item.is_dir():
                # Recurse into subdirectories
                new_prefix = f"{prefix}/{item.name}" if prefix else item.name
                self._scan_directory(item, module_type, new_prefix, path_root=root)

            elif item.suffix == ".py":
                # Found a module file
                module_name = item.stem
                if prefix:
                    full_path = f"{root}/{prefix}/{module_name}"
                else:
                    full_path = f"{root}/{module_name}"

                info = self._extract_module_info(item, full_path, module_type)
                if info:
                    self._module_cache[full_path] = info

    def _register_virtual_modules(self) -> None:
        """Scan for base files with VIRTUAL_MODULES registries.

        Base files (named _*_base.py or _base.py) can export a
        VIRTUAL_MODULES dict to auto-register tool wrappers without
        needing individual stub files.
        """
        for base_file in self.modules_path.rglob("_*_base.py"):
            try:
                content = base_file.read_text()
                if "VIRTUAL_MODULES" not in content:
                    continue

                # Import the base file to get the registry
                mod_name = f"_uwu_base_{base_file.stem}"
                spec = importlib.util.spec_from_file_location(mod_name, base_file)
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                # Avoid polluting sys.modules with temp name
                old_mod = sys.modules.get(mod_name)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)

                vm = getattr(mod, "VIRTUAL_MODULES", None)
                if not vm or not isinstance(vm, dict):
                    continue

                for vpath, vinfo in vm.items():
                    if vpath in self._module_cache:
                        continue  # Real file takes precedence
                    self._module_cache[vpath] = ModuleInfo(
                        path=vpath,
                        file_path=base_file,
                        name=vinfo.get("name", vpath.split("/")[-1]),
                        description=vinfo.get("description", "No description"),
                        module_type=ModuleType.AUXILIARY,
                        tags=vinfo.get("tags", []),
                        platform=vinfo.get("platform", "windows"),
                        author=vinfo.get("author", "UwU Toolkit"),
                        virtual_key=vinfo.get("tool_key", ""),
                    )

                    # Register backward-compat alias if applicable
                    alias = vinfo.get("alias", "")
                    if alias and alias != vpath:
                        self._path_aliases[alias] = vpath

                # Clean up
                if old_mod is not None:
                    sys.modules[mod_name] = old_mod
                else:
                    sys.modules.pop(mod_name, None)

            except Exception as e:
                print(f"[!] Error loading virtual modules from {base_file}: {e}")

    def _extract_module_info(
        self,
        file_path: Path,
        module_path: str,
        module_type: ModuleType
    ) -> Optional[ModuleInfo]:
        """Extract module info without fully loading it"""
        try:
            # Read file and look for metadata
            content = file_path.read_text()

            # Quick extraction from docstring or variables
            name = file_path.stem
            description = "No description"
            tags = []
            platform = "multi"
            author = "Unknown"

            # Look for common patterns
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("self.name"):
                    name = self._extract_string_value(line) or name
                elif line.startswith("self.description"):
                    description = self._extract_string_value(line) or description
                elif line.startswith("self.author"):
                    author = self._extract_string_value(line) or author
                elif "self.tags" in line and "[" in line:
                    tags = self._extract_list_value(line)
                elif "Platform." in line:
                    for p in ["WINDOWS", "LINUX", "MACOS", "MULTI", "WEB", "NETWORK"]:
                        if f"Platform.{p}" in line:
                            platform = p.lower()
                            break

            return ModuleInfo(
                path=module_path,
                file_path=file_path,
                name=name,
                description=description,
                module_type=module_type,
                tags=tags,
                platform=platform,
                author=author
            )

        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}")
            return None

    def _extract_string_value(self, line: str) -> Optional[str]:
        """Extract string value from assignment"""
        for quote in ['"', "'"]:
            if quote in line:
                parts = line.split(quote)
                if len(parts) >= 2:
                    return parts[1]
        return None

    def _extract_list_value(self, line: str) -> List[str]:
        """Extract list value from assignment"""
        try:
            if "[" in line and "]" in line:
                start = line.index("[")
                end = line.rindex("]") + 1
                list_str = line[start:end]
                return ast.literal_eval(list_str)
        except:
            pass
        return []

    def _resolve_path(self, module_path: str) -> str:
        """Resolve a module path, handling aliases and backward compatibility."""
        # Direct match
        if module_path in self._module_cache:
            return module_path

        # Check aliases (old path -> new path)
        if module_path in self._path_aliases:
            return self._path_aliases[module_path]

        # Backward compat: try stripping "auxiliary/" prefix
        # e.g., "auxiliary/impacket/psexec" -> "impacket/psexec"
        if module_path.startswith("auxiliary/"):
            alt = module_path[len("auxiliary/"):]
            if alt in self._module_cache:
                return alt

        return module_path

    def load_module(self, module_path: str) -> Optional[ModuleBase]:
        """
        Load and instantiate a module by path

        Args:
            module_path: Full module path (e.g., "impacket/psexec", "ad/kerberoast")

        Returns:
            Instantiated module or None if not found/error
        """
        # Resolve aliases and backward-compat paths
        resolved = self._resolve_path(module_path)

        # Check loaded cache
        if resolved in self._loaded_modules:
            return self._loaded_modules[resolved]

        # Find module info
        if resolved not in self._module_cache:
            self.discover_modules()
            resolved = self._resolve_path(module_path)
            if resolved not in self._module_cache:
                return None

        info = self._module_cache[resolved]

        # Virtual module: instantiate base class with tool_key
        if info.virtual_key:
            return self._load_virtual_module(info, resolved)

        try:
            # Load the module file
            spec = importlib.util.spec_from_file_location(
                f"uwu_modules.{resolved.replace('/', '.')}",
                info.file_path
            )
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Find and instantiate the module class
            # Try each ModuleBase subclass - skip base classes that require args
            candidates = []
            for attr_name in dir(module):
                if attr_name.startswith('_'):
                    continue
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, ModuleBase) and
                    attr is not ModuleBase):
                    candidates.append(attr)

            if not candidates:
                print(f"[!] No ModuleBase subclass found in {resolved}")
                return None

            # Try to instantiate each candidate - the actual module class
            # will work, imported base classes requiring args will be skipped
            instance = None
            for cls in candidates:
                try:
                    instance = cls()
                    break
                except TypeError:
                    continue

            if not instance:
                print(f"[!] Could not instantiate any class in {resolved}")
                return None

            self._loaded_modules[resolved] = instance
            return instance

        except Exception as e:
            print(f"[!] Error loading module {resolved}: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _load_virtual_module(self, info: ModuleInfo, resolved_path: str) -> Optional[ModuleBase]:
        """Load a virtual module by instantiating the base class with a tool_key."""
        try:
            # Load the base file
            mod_name = f"uwu_modules.{resolved_path.replace('/', '.')}"
            spec = importlib.util.spec_from_file_location(mod_name, info.file_path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Find ModuleBase subclasses that accept a tool_key argument
            candidates = []
            for attr_name in dir(module):
                if attr_name.startswith('_'):
                    continue
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, ModuleBase) and
                    attr is not ModuleBase):
                    candidates.append(attr)

            instance = None
            for cls in candidates:
                try:
                    instance = cls(info.virtual_key)
                    break
                except TypeError:
                    continue

            if not instance:
                print(f"[!] Could not instantiate virtual module {resolved_path} "
                      f"(key={info.virtual_key})")
                return None

            self._loaded_modules[resolved_path] = instance
            return instance

        except Exception as e:
            print(f"[!] Error loading virtual module {resolved_path}: {e}")
            import traceback
            traceback.print_exc()
            return None

    def reload_module(self, module_path: str) -> Optional[ModuleBase]:
        """Reload a module (useful during development)"""
        resolved = self._resolve_path(module_path)

        # Remove from loaded cache
        if resolved in self._loaded_modules:
            del self._loaded_modules[resolved]

        # Clear from sys.modules so Python actually re-reads the file
        mod_name = f"uwu_modules.{resolved.replace('/', '.')}"
        to_remove = [k for k in sys.modules if k.startswith(mod_name) or k == mod_name]
        for k in to_remove:
            del sys.modules[k]

        # Also clear base modules that may have been updated
        if resolved in self._module_cache:
            info = self._module_cache[resolved]
            base_dir = info.file_path.parent
            # Clear any _*_base modules from the same directory
            for k in list(sys.modules.keys()):
                if hasattr(sys.modules[k], '__file__') and sys.modules[k].__file__:
                    mod_file = sys.modules[k].__file__
                    if mod_file and str(base_dir) in mod_file and '_base' in mod_file:
                        del sys.modules[k]

        return self.load_module(resolved)

    def reload_all(self) -> int:
        """Reload all modules - rediscover and clear all caches.

        Returns: number of modules discovered
        """
        # Clear all caches
        self._loaded_modules.clear()

        # Clear all uwu module entries from sys.modules
        to_remove = [k for k in sys.modules if k.startswith("uwu_modules.")]
        for k in to_remove:
            del sys.modules[k]

        # Also clear any base modules
        to_remove = [k for k in sys.modules
                     if k.startswith("modules.") or
                     k.startswith("_uwu_base_") or
                     (hasattr(sys.modules[k], '__file__') and sys.modules[k].__file__ and
                      str(self.modules_path) in str(sys.modules[k].__file__ or ''))]
        for k in to_remove:
            del sys.modules[k]

        # Rediscover
        self.discover_modules()
        return len(self._module_cache)

    def search(
        self,
        query: str,
        module_type: Optional[ModuleType] = None,
        platform: Optional[str] = None
    ) -> List[ModuleInfo]:
        """
        Search modules by name, description, or tags

        Args:
            query: Search term
            module_type: Filter by module type
            platform: Filter by platform

        Returns:
            List of matching ModuleInfo
        """
        query = query.lower()
        results = []

        for path, info in self._module_cache.items():
            # Type filter
            if module_type and info.module_type != module_type:
                continue

            # Platform filter
            if platform and info.platform.lower() != platform.lower():
                continue

            # Search in name, description, tags, and path
            searchable = [
                info.name.lower(),
                info.description.lower(),
                info.path.lower(),
                info.platform.lower(),
                *[t.lower() for t in info.tags]
            ]

            if any(query in s for s in searchable):
                results.append(info)

        return results

    def get_all_modules(self) -> Dict[str, ModuleInfo]:
        """Get all discovered modules"""
        return self._module_cache.copy()

    def get_modules_by_type(self, module_type: ModuleType) -> List[ModuleInfo]:
        """Get all modules of a specific type"""
        return [
            info for info in self._module_cache.values()
            if info.module_type == module_type
        ]

    def get_module_types(self) -> Dict[str, int]:
        """Get count of modules by type"""
        counts = {}
        for module_type in ModuleType:
            count = len(self.get_modules_by_type(module_type))
            counts[module_type.value] = count
        return counts

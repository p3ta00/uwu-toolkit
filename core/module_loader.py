"""
Module loader and manager for UwU Toolkit
Handles discovery, loading, and searching of modules
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from .module_base import ModuleBase, ModuleType


@dataclass
class ModuleInfo:
    """Lightweight module metadata (loaded without instantiating)"""
    path: str  # Full path like "auxiliary/scanner/smb_enum"
    file_path: Path  # Actual file path
    name: str
    description: str
    module_type: ModuleType
    tags: List[str]
    platform: str
    author: str


class ModuleLoader:
    """Discovers, loads, and manages modules"""

    def __init__(self, modules_path: str):
        self.modules_path = Path(modules_path)
        self._module_cache: Dict[str, ModuleInfo] = {}
        self._loaded_modules: Dict[str, ModuleBase] = {}

    def discover_modules(self) -> Dict[str, ModuleInfo]:
        """
        Discover all available modules

        Returns dict of module_path -> ModuleInfo
        """
        self._module_cache.clear()

        for module_type in ModuleType:
            type_dir = self.modules_path / module_type.value
            if not type_dir.exists():
                type_dir.mkdir(parents=True, exist_ok=True)
                continue

            self._scan_directory(type_dir, module_type)

        return self._module_cache

    def _scan_directory(self, directory: Path, module_type: ModuleType, prefix: str = "") -> None:
        """Recursively scan directory for modules"""
        for item in directory.iterdir():
            if item.name.startswith("_") or item.name.startswith("."):
                continue

            if item.is_dir():
                # Recurse into subdirectories
                new_prefix = f"{prefix}/{item.name}" if prefix else item.name
                self._scan_directory(item, module_type, new_prefix)

            elif item.suffix == ".py":
                # Found a module file
                module_name = item.stem
                if prefix:
                    full_path = f"{module_type.value}/{prefix}/{module_name}"
                else:
                    full_path = f"{module_type.value}/{module_name}"

                info = self._extract_module_info(item, full_path, module_type)
                if info:
                    self._module_cache[full_path] = info

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
                # Safe eval for simple lists
                return eval(list_str)
        except:
            pass
        return []

    def load_module(self, module_path: str) -> Optional[ModuleBase]:
        """
        Load and instantiate a module by path

        Args:
            module_path: Full module path (e.g., "auxiliary/scanner/smb_enum")

        Returns:
            Instantiated module or None if not found/error
        """
        # Check cache first
        if module_path in self._loaded_modules:
            return self._loaded_modules[module_path]

        # Find module info
        if module_path not in self._module_cache:
            # Try to discover
            self.discover_modules()
            if module_path not in self._module_cache:
                return None

        info = self._module_cache[module_path]

        try:
            # Load the module file
            spec = importlib.util.spec_from_file_location(
                f"uwu_modules.{module_path.replace('/', '.')}",
                info.file_path
            )
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Find the module class (should be the first ModuleBase subclass)
            module_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, ModuleBase) and
                    attr is not ModuleBase):
                    module_class = attr
                    break

            if not module_class:
                print(f"[!] No ModuleBase subclass found in {module_path}")
                return None

            # Instantiate
            instance = module_class()
            self._loaded_modules[module_path] = instance
            return instance

        except Exception as e:
            print(f"[!] Error loading module {module_path}: {e}")
            import traceback
            traceback.print_exc()
            return None

    def reload_module(self, module_path: str) -> Optional[ModuleBase]:
        """Reload a module (useful during development)"""
        if module_path in self._loaded_modules:
            del self._loaded_modules[module_path]
        return self.load_module(module_path)

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

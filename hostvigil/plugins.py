"""
HostVigil Plugin Architecture - Auto-discovers and loads plugins from plugins/ directory.

Plugin types:
- DiscoveryPlugin: Custom host discovery techniques
- ScannerPlugin: Custom port/service scanning
- AnalysisPlugin: Custom analysis/correlation logic

Usage:
    from hostvigil.plugins import PluginManager
    pm = PluginManager('plugins')
    print(pm.get_all_plugins())
    results = pm.run_discovery_plugins(target_ranges, config)
"""

import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("hostvigil.plugins")


# ---------------------------------------------------------------------------
# Plugin interface base classes
# ---------------------------------------------------------------------------


class DiscoveryPlugin:
    """Base class for discovery plugins.

    Subclass this and implement discover() to create a custom discovery technique.
    Place the file in the plugins/ directory and it will be auto-loaded.
    """

    name: str = "unnamed"
    description: str = ""

    def discover(self, target_ranges: List[str], config: dict) -> List[Dict]:
        """Run discovery. Return list of {ip, hostname, mac, method} dicts."""
        raise NotImplementedError


class ScannerPlugin:
    """Base class for scanner plugins.

    Subclass this and implement scan() to create a custom scanner.
    Place the file in the plugins/ directory and it will be auto-loaded.
    """

    name: str = "unnamed"
    description: str = ""

    def scan(self, hosts: List[str], config: dict) -> List[Dict]:
        """Run scan. Return list of {ip, port, state, service, banner} dicts."""
        raise NotImplementedError


class AnalysisPlugin:
    """Base class for analysis plugins.

    Subclass this and implement analyze() to create a custom analysis module.
    Place the file in the plugins/ directory and it will be auto-loaded.
    """

    name: str = "unnamed"
    description: str = ""

    def analyze(self, db_path: str, config: dict) -> List[Dict]:
        """Run analysis. Return list of findings."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Plugin Manager
# ---------------------------------------------------------------------------


class PluginManager:
    """Discovers and manages plugins from the plugins/ directory.

    On initialization, scans the plugin directory for .py files (ignoring those
    starting with _), imports them, and registers any classes that subclass
    DiscoveryPlugin, ScannerPlugin, or AnalysisPlugin.
    """

    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugin_dir.mkdir(exist_ok=True)
        self.discovery_plugins: List[DiscoveryPlugin] = []
        self.scanner_plugins: List[ScannerPlugin] = []
        self.analysis_plugins: List[AnalysisPlugin] = []
        self._loaded_modules: Dict[str, Any] = {}
        self._load_plugins()

    def _load_plugins(self):
        """Scan plugin directory and load all valid plugins."""
        if not self.plugin_dir.exists():
            return

        # Resolve the plugin directory to an absolute path for safe comparisons
        resolved_plugin_dir = self.plugin_dir.resolve()

        for py_file in sorted(self.plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            # Security: skip symlinks to prevent loading files from outside the plugin dir
            if py_file.is_symlink():
                logger.warning(f"Skipping symlinked plugin file: {py_file.name}")
                continue

            # Security: ensure the resolved path is within the plugin directory
            try:
                resolved_file = py_file.resolve(strict=True)
                if not str(resolved_file).startswith(str(resolved_plugin_dir)):
                    logger.warning(f"Skipping plugin outside plugin dir: {py_file.name}")
                    continue
            except (OSError, ValueError):
                logger.warning(f"Cannot resolve plugin path: {py_file.name}")
                continue

            self._load_plugin_file(py_file)

        total = len(self.discovery_plugins) + len(self.scanner_plugins) + len(self.analysis_plugins)
        if total > 0:
            logger.info(f"Loaded {total} plugin(s) from {self.plugin_dir}")

    def _load_plugin_file(self, path: Path):
        """Load a single plugin file and register its classes."""
        module_name = f"hostvigil_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.warning(f"Cannot load plugin {path.name}: invalid module spec")
                return

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._loaded_modules[path.stem] = module

            # Find and register plugin classes
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if not isinstance(attr, type):
                    continue

                if issubclass(attr, DiscoveryPlugin) and attr is not DiscoveryPlugin:
                    instance = attr()
                    self.discovery_plugins.append(instance)
                    logger.info(f"Loaded discovery plugin: {instance.name}")
                elif issubclass(attr, ScannerPlugin) and attr is not ScannerPlugin:
                    instance = attr()
                    self.scanner_plugins.append(instance)
                    logger.info(f"Loaded scanner plugin: {instance.name}")
                elif issubclass(attr, AnalysisPlugin) and attr is not AnalysisPlugin:
                    instance = attr()
                    self.analysis_plugins.append(instance)
                    logger.info(f"Loaded analysis plugin: {instance.name}")

        except Exception as e:
            logger.error(f"Failed to load plugin {path.name}: {e}")

    def get_all_plugins(self) -> Dict:
        """Return summary of all loaded plugins."""
        return {
            "discovery": [{"name": p.name, "description": p.description} for p in self.discovery_plugins],
            "scanner": [{"name": p.name, "description": p.description} for p in self.scanner_plugins],
            "analysis": [{"name": p.name, "description": p.description} for p in self.analysis_plugins],
            "total": len(self.discovery_plugins) + len(self.scanner_plugins) + len(self.analysis_plugins),
        }

    def run_discovery_plugins(self, target_ranges: List[str], config: dict) -> List[Dict]:
        """Run all discovery plugins and aggregate results."""
        results = []
        for plugin in self.discovery_plugins:
            try:
                found = plugin.discover(target_ranges, config)
                if found:
                    results.extend(found)
                    logger.info(f"Discovery plugin {plugin.name} found {len(found)} host(s)")
            except Exception as e:
                logger.error(f"Discovery plugin {plugin.name} failed: {e}")
        return results

    def run_scanner_plugins(self, hosts: List[str], config: dict) -> List[Dict]:
        """Run all scanner plugins and aggregate results."""
        results = []
        for plugin in self.scanner_plugins:
            try:
                found = plugin.scan(hosts, config)
                if found:
                    results.extend(found)
                    logger.info(f"Scanner plugin {plugin.name} found {len(found)} result(s)")
            except Exception as e:
                logger.error(f"Scanner plugin {plugin.name} failed: {e}")
        return results

    def run_analysis_plugins(self, db_path: str, config: dict) -> List[Dict]:
        """Run all analysis plugins and aggregate results."""
        results = []
        for plugin in self.analysis_plugins:
            try:
                found = plugin.analyze(db_path, config)
                if found:
                    results.extend(found)
                    logger.info(f"Analysis plugin {plugin.name} produced {len(found)} finding(s)")
            except Exception as e:
                logger.error(f"Analysis plugin {plugin.name} failed: {e}")
        return results

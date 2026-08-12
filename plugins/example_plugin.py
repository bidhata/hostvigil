"""
Example HostVigil plugin - demonstrates the plugin interface.

To create your own plugin:
1. Create a .py file in this directory
2. Import the base class from hostvigil.plugins
3. Create a class that inherits from the base class
4. Implement the required method (discover/scan/analyze)

The PluginManager will automatically discover and load your plugin.
"""

from hostvigil.plugins import DiscoveryPlugin


class ExampleDiscovery(DiscoveryPlugin):
    """Example discovery plugin that demonstrates the interface.

    This plugin does nothing - replace with your own discovery logic.
    For example: custom SNMP community string probes, proprietary
    protocol discovery, or integration with external tools.
    """

    name = "example"
    description = "Example discovery plugin (does nothing - template only)"

    def discover(self, target_ranges, config):
        """Discover hosts using your custom technique.

        Args:
            target_ranges: List of CIDR ranges to scan (e.g., ['10.0.0.0/24'])
            config: Configuration dict from config.yaml

        Returns:
            List of dicts with keys: ip, hostname (optional), mac (optional), method
        """
        # Your custom discovery logic here
        # Example:
        # return [{'ip': '10.0.0.1', 'hostname': 'router.local', 'method': 'example'}]
        return []

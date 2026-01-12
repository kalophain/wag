"""Route key structures for network routing."""

import ipaddress
from typing import Union


class Key:
    """
    Represents a routing key with an IP prefix.
    
    The key contains a prefix length and IP address bytes,
    used for routing table lookups.
    """
    
    def __init__(self, prefixlen: int, ip: bytes):
        """
        Initialize a routing key.
        
        Args:
            prefixlen: The prefix length (0-32 for IPv4, 0-128 for IPv6)
            ip: The IP address as bytes
        """
        self.prefixlen = prefixlen
        self.ip = ip
    
    def to_prefix(self) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        """
        Convert the key to an IP network prefix.
        
        Returns:
            IPv4Network or IPv6Network object
        """
        addr = ipaddress.ip_address(self.ip)
        return ipaddress.ip_network(f"{addr}/{self.prefixlen}", strict=False)
    
    def as_ipv4(self) -> Union[ipaddress.IPv4Address, None]:
        """
        Return as IPv4 address if applicable.
        
        Returns:
            IPv4Address if the IP is IPv4, None otherwise
        """
        try:
            addr = ipaddress.ip_address(self.ip)
            if isinstance(addr, ipaddress.IPv4Address):
                return addr
        except ValueError:
            pass
        return None
    
    def as_ipv6(self) -> Union[ipaddress.IPv6Address, None]:
        """
        Return as IPv6 address if applicable.
        
        Returns:
            IPv6Address if the IP is IPv6, None otherwise
        """
        try:
            addr = ipaddress.ip_address(self.ip)
            if isinstance(addr, ipaddress.IPv6Address):
                return addr
        except ValueError:
            pass
        return None
    
    def as_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """
        Return as IP address (either v4 or v6).
        
        Returns:
            IPv4Address or IPv6Address
        """
        return ipaddress.ip_address(self.ip)
    
    def __str__(self) -> str:
        """String representation of the key."""
        return f"{ipaddress.ip_address(self.ip)}/{self.prefixlen}"
    
    def __eq__(self, other) -> bool:
        """Check equality with another Key."""
        if not isinstance(other, Key):
            return False
        return self.prefixlen == other.prefixlen and self.ip == other.ip
    
    def __hash__(self) -> int:
        """Make Key hashable for use in sets and dicts."""
        return hash((self.prefixlen, self.ip))

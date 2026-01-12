"""Policy types and operations for network access control."""

import struct
from typing import Optional

# Protocol constants
ICMP = 1  # Internet Control Message
TCP = 6   # Transmission Control
UDP = 17  # User Datagram

# Policy type constants
ANY = 0

# Policy type flags (using bit shifts like Go)
PUBLIC = 1 << 0  # 1
RANGE = 1 << 1   # 2
SINGLE = 1 << 2  # 4
DENY = 1 << 3    # 8

PolicyType = int


class Policy:
    """
    Represents a network access policy with protocol and port information.
    
    Format matches the Go struct:
    struct range {
        __u16 policy_type;
        __u16 proto;
        __u16 lower_port;
        __u16 upper_port;
    };
    """
    
    def __init__(
        self,
        policy_type: int = 0,
        proto: int = 0,
        lower_port: int = 0,
        upper_port: int = 0
    ):
        """
        Initialize a policy.
        
        Args:
            policy_type: Policy type flags (PUBLIC, RANGE, SINGLE, DENY, etc.)
            proto: Protocol number (TCP, UDP, ICMP, etc.)
            lower_port: Lower port number (or single port)
            upper_port: Upper port number (for ranges)
        """
        self.policy_type = policy_type
        self.proto = proto
        self.lower_port = lower_port
        self.upper_port = upper_port
    
    def is_type(self, pt: PolicyType) -> bool:
        """
        Check if policy has a specific type flag set.
        
        Args:
            pt: Policy type to check
            
        Returns:
            True if the policy type flag is set
        """
        if self.policy_type == 0 and pt == 0:
            return True
        return (self.policy_type & pt) != 0
    
    def to_bytes(self) -> bytes:
        """
        Convert policy to bytes (little-endian format).
        
        Returns:
            8 bytes representing the policy struct
        """
        return struct.pack(
            '<HHHH',  # 4 unsigned shorts, little-endian
            self.policy_type,
            self.proto,
            self.lower_port,
            self.upper_port
        )
    
    def from_bytes(self, data: bytes) -> None:
        """
        Unpack policy from bytes (little-endian format).
        
        Args:
            data: Bytes to unpack (must be at least 8 bytes)
            
        Raises:
            ValueError: If data is too short
        """
        if len(data) < 8:
            raise ValueError("firewall policy is too short")
        
        self.policy_type, self.proto, self.lower_port, self.upper_port = struct.unpack(
            '<HHHH',
            data[:8]
        )
    
    def _lookup_protocol(self) -> str:
        """Look up protocol name from number."""
        proto_map = {
            ANY: "any",
            TCP: "tcp",
            UDP: "udp",
            ICMP: "icmp",
        }
        return proto_map.get(self.proto, f"unknown({self.proto})")
    
    def __str__(self) -> str:
        """String representation of the policy."""
        restriction_type = "mfa"
        
        if self.is_type(PUBLIC):
            restriction_type = "public"
        
        if self.is_type(DENY):
            restriction_type = "deny"
        
        if self.is_type(SINGLE):
            port = str(self.lower_port) if self.lower_port != 0 else "any"
            return f"{restriction_type}({self.policy_type}) {port}/{self._lookup_protocol()}"
        
        if self.is_type(RANGE):
            return f"{restriction_type}({self.policy_type}) {self.lower_port}-{self.upper_port}/{self._lookup_protocol()}"
        
        return "unknown policy"
    
    def __eq__(self, other) -> bool:
        """Check equality with another Policy."""
        if not isinstance(other, Policy):
            return False
        return (
            self.policy_type == other.policy_type and
            self.proto == other.proto and
            self.lower_port == other.lower_port and
            self.upper_port == other.upper_port
        )
    
    def __hash__(self) -> int:
        """Make Policy hashable."""
        return hash((self.policy_type, self.proto, self.lower_port, self.upper_port))

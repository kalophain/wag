"""Parser for network access rules and policies."""

import hashlib
import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass

from .key import Key
from .policy import ANY, DENY, ICMP, PUBLIC, RANGE, SINGLE, TCP, UDP, Policy, PolicyType


@dataclass
class Rule:
    """
    Represents a routing rule with keys (IP prefixes) and policies.
    """

    keys: list[Key]
    values: list[Policy]


# Global cache for parsed rules
_cache_lock = threading.RLock()
_global_cache: dict[str, list[Rule]] = {}

# DNS cache for domain resolution
_dns_lock = threading.RLock()
_dns_cache: dict[str, tuple[float, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]] = {}


def _hash_rules(mfa: list[str], public: list[str], deny: list[str]) -> str:
    """
    Create a hash of the rule lists for caching.

    Args:
        mfa: List of MFA-protected rules
        public: List of public rules
        deny: List of deny rules

    Returns:
        SHA1 hash of the sorted rules
    """
    mfa_sorted = sorted(mfa)
    public_sorted = sorted(public)
    deny_sorted = sorted(deny)

    data = json.dumps([mfa_sorted, public_sorted, deny_sorted])
    return hashlib.sha1(data.encode()).hexdigest()


def parse_rules(mfa: list[str], public: list[str], deny: list[str]) -> tuple[list[Rule], list[Exception]]:
    """
    Parse firewall rules from MFA, public, and deny rule lists.

    Args:
        mfa: List of MFA-protected access rules (e.g., ["10.0.0.0/8 80/tcp"])
        public: List of public access rules
        deny: List of deny rules

    Returns:
        Tuple of (list of parsed rules, list of errors)
    """
    cache_key = _hash_rules(mfa, public, deny)

    # Check cache
    with _cache_lock:
        if cache_key in _global_cache:
            return _global_cache[cache_key], []

    result: list[Rule] = []
    errors: list[Exception] = []
    cache: dict[str, int] = {}

    # Parse MFA rules (restriction type 0 = MFA)
    for rule_str in mfa:
        try:
            rule = _parse_rule(0, rule_str)
            for key in rule.keys:
                key_str = str(key)
                if key_str in cache:
                    # Add policies to existing rule with same key
                    result[cache[key_str]].values.extend(rule.values)
                else:
                    result.append(rule)
                    cache[key_str] = len(result) - 1
        except Exception as e:
            errors.append(e)

    # Parse public rules
    for rule_str in public:
        try:
            rule = _parse_rule(PUBLIC, rule_str)
            for key in rule.keys:
                key_str = str(key)
                if key_str in cache:
                    result[cache[key_str]].values.extend(rule.values)
                else:
                    result.append(rule)
                    cache[key_str] = len(result) - 1
        except Exception as e:
            errors.append(e)

    # Parse deny rules
    for rule_str in deny:
        try:
            rule = _parse_rule(DENY, rule_str)
            for key in rule.keys:
                key_str = str(key)
                if key_str in cache:
                    result[cache[key_str]].values.extend(rule.values)
                else:
                    result.append(rule)
                    cache[key_str] = len(result) - 1
        except Exception as e:
            errors.append(e)

    # Cache if no errors
    if not errors:
        with _cache_lock:
            _global_cache[cache_key] = result

    return result, errors


def validate_rules(mfa: list[str], public: list[str], deny: list[str]) -> str | None:
    """
    Validate firewall rules and return error message if invalid.

    Args:
        mfa: List of MFA-protected rules
        public: List of public rules
        deny: List of deny rules

    Returns:
        Error message string if validation fails, None if valid
    """
    _, errors = parse_rules(mfa, public, deny)

    if not errors:
        return None

    return "\n".join(str(e) for e in errors)


def acls_to_routes(rules: list[str]) -> tuple[list[str], Exception | None]:
    """
    Extract unique routes (IP prefixes) from ACL rules.

    Args:
        rules: List of ACL rules

    Returns:
        Tuple of (list of unique routes, error if any)
    """
    deduplication = set()
    routes = []

    for rule in rules:
        parts = rule.split()
        if len(parts) < 1:
            return [], ValueError("could not split correct number of rules")

        try:
            keys = _parse_keys(parts[0])
        except Exception as e:
            return [], Exception(f"could not parse address {parts[0]}: {e}")

        for key in keys:
            key_str = str(key)
            if key_str not in deduplication:
                deduplication.add(key_str)
                routes.append(key_str)

    return routes, None


def _parse_rule(restriction_type: PolicyType, rule: str) -> Rule:
    """
    Parse a single rule string into a Rule object.

    Args:
        restriction_type: Type of restriction (0=MFA, PUBLIC, DENY)
        rule: Rule string (e.g., "10.0.0.0/8 80/tcp 443/tcp")

    Returns:
        Parsed Rule object

    Raises:
        ValueError: If rule is malformed
    """
    parts = rule.split()
    if len(parts) < 1:
        raise ValueError("could not split correct number of rules")

    keys = _parse_keys(parts[0])

    if len(parts) == 1:
        # Only address, no ports = any/any rule
        values = [Policy(policy_type=restriction_type | SINGLE, proto=ANY, lower_port=ANY)]
    else:
        values = []
        for field in parts[1:]:
            policy = _parse_service(field)
            policy.policy_type = restriction_type | policy.policy_type
            values.append(policy)

    return Rule(keys=keys, values=values)


def _parse_keys(address: str) -> list[Key]:
    """
    Parse an address string into Key objects.

    Args:
        address: Address string (IP, CIDR, or domain)

    Returns:
        List of Key objects

    Raises:
        ValueError: If address is invalid
    """
    networks = _parse_address(address)
    keys = []

    for network in networks:
        keys.append(Key(prefixlen=network.prefixlen, ip=network.network_address.packed))

    return keys


def _parse_address(address: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse an address string into IP networks.

    Handles IP addresses, CIDR notation, and domain names (with DNS lookup).

    Args:
        address: Address string

    Returns:
        List of IP networks

    Raises:
        ValueError: If address cannot be parsed or resolved
    """
    # Try parsing as IP address first
    try:
        addr = ipaddress.ip_address(address)
        if isinstance(addr, ipaddress.IPv4Address):
            return [ipaddress.IPv4Network(f"{addr}/32", strict=False)]
        else:
            return [ipaddress.IPv6Network(f"{addr}/128", strict=False)]
    except ValueError:
        pass

    # Try parsing as CIDR
    try:
        network = ipaddress.ip_network(address, strict=False)
        return [network]
    except ValueError:
        pass

    # Try DNS lookup with caching
    with _dns_lock:
        if address in _dns_cache:
            cache_time, cached_addresses = _dns_cache[address]
            if time.time() - cache_time < 3.0:  # 3 second cache
                return cached_addresses

    # Perform DNS lookup
    try:
        addr_info = socket.getaddrinfo(address, None)
    except socket.gaierror as e:
        raise ValueError(f"unable to resolve address from: {address}") from e

    if not addr_info:
        raise ValueError(f"no addresses for {address}")

    result_addresses = []
    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv4Address):
                result_addresses.append(ipaddress.IPv4Network(f"{addr}/32", strict=False))
            elif isinstance(addr, ipaddress.IPv6Address):
                result_addresses.append(ipaddress.IPv6Network(f"{addr}/128", strict=False))
        except ValueError:
            continue

    if not result_addresses:
        raise ValueError(f"no addresses for domain {address} were added")

    # Cache the result
    with _dns_lock:
        _dns_cache[address] = (time.time(), result_addresses)

    return result_addresses


def _parse_service(service: str) -> Policy:
    """
    Parse a service/port specification into a Policy.

    Args:
        service: Service string (e.g., "80/tcp", "8000-9000/tcp", "icmp")

    Returns:
        Parsed Policy object

    Raises:
        ValueError: If service specification is invalid
    """
    parts = service.split("/")

    # Handle protocol-only specs like "icmp"
    if len(parts) == 1:
        if parts[0] == "icmp":
            return Policy(policy_type=SINGLE, proto=ICMP, lower_port=0)
        else:
            raise ValueError(f"malformed port/service declaration: {service}")

    # Parse port and protocol
    port_spec = parts[0]
    proto = parts[1].lower()

    # Check if it's a port range
    if "-" in port_spec:
        port_range = port_spec.split("-")
        return _parse_port_range(port_range[0], port_range[1], proto)
    else:
        return _parse_single_port(port_spec, proto)


def _parse_port_range(lower_port: str, upper_port: str, proto: str) -> Policy:
    """
    Parse a port range policy.

    Args:
        lower_port: Lower port number string
        upper_port: Upper port number string
        proto: Protocol name (tcp, udp, any)

    Returns:
        Parsed Policy object

    Raises:
        ValueError: If ports or protocol are invalid
    """
    try:
        lower_port_num = int(lower_port)
    except ValueError:
        raise ValueError(f"could not convert lower port definition to number: {lower_port}")

    try:
        upper_port_num = int(upper_port)
    except ValueError:
        raise ValueError(f"could not convert upper port definition to number: {upper_port}")

    if lower_port_num > upper_port_num:
        raise ValueError(f"lower port cannot be higher than upper port: lower: {lower_port} upper: {upper_port}")

    if proto == "any":
        return Policy(policy_type=RANGE, proto=ANY, lower_port=lower_port_num, upper_port=upper_port_num)
    elif proto in ("tcp", "udp"):
        proto_num = TCP if proto == "tcp" else UDP
        return Policy(policy_type=RANGE, proto=proto_num, lower_port=lower_port_num, upper_port=upper_port_num)
    else:
        raise ValueError(f"unknown service: {proto}")


def _parse_single_port(port: str, proto: str) -> Policy:
    """
    Parse a single port policy.

    Args:
        port: Port number string
        proto: Protocol name (tcp, udp, any)

    Returns:
        Parsed Policy object

    Raises:
        ValueError: If port or protocol are invalid
    """
    try:
        port_number = int(port)
    except ValueError:
        raise ValueError(f"could not convert port definition to number: {port}")

    if proto == "any":
        return Policy(policy_type=SINGLE, proto=ANY, lower_port=port_number)
    elif proto in ("tcp", "udp"):
        proto_num = TCP if proto == "tcp" else UDP
        return Policy(policy_type=SINGLE, proto=proto_num, lower_port=port_number)
    else:
        raise ValueError(f"unknown service: {port}/{proto}")

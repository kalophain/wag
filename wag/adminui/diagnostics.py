"""Diagnostics endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import (
    WgDevicesData, FirewallTestRequestDTO, GenericResponseDTO,
    AclsTestRequestDTO, AclsTestResponseDTO, TestNotificationsRequestDTO
)

logger = logging.getLogger(__name__)


async def wg_diagnostics_data(ctrl_client, firewall, request: Request) -> List[WgDevicesData]:
    """Get WireGuard diagnostics data."""
    try:
        if not firewall:
            raise HTTPException(status_code=500, detail="Firewall not available")
        
        peers = await firewall.list_peers()
        wireguard_peers = []
        
        for peer in peers:
            ip = "-"
            if peer.allowed_ips and len(peer.allowed_ips) > 0:
                ip = str(peer.allowed_ips[0])
            
            wireguard_peers.append(WgDevicesData(
                rx=peer.receive_bytes,
                tx=peer.transmit_bytes,
                public_key=str(peer.public_key),
                address=ip,
                last_endpoint=str(peer.endpoint) if peer.endpoint else "",
                last_handshake_time=peer.last_handshake_time.strftime("%a, %d %b %Y %H:%M:%S") if peer.last_handshake_time else ""
            ))
        
        return wireguard_peers
    except Exception as e:
        logger.error(f"Error getting WireGuard diagnostics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_firewall_state(ctrl_client, request: Request) -> List[dict]:
    """Get firewall state."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        rules = await ctrl_client.firewall_rules()
        return rules
    except Exception as e:
        logger.error(f"Error getting firewall state: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def firewall_check_test(ctrl_client, firewall, request: Request, test: FirewallTestRequestDTO) -> GenericResponseDTO:
    """Test firewall check."""
    try:
        if not firewall:
            raise HTTPException(status_code=500, detail="Firewall not available")
        
        # Validate input
        # Basic validation - actual Go code uses validator library
        if not test.address or not test.protocol or not test.target:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        decision = await firewall.check_route(test.address, test.target, test.protocol, test.port)
        
        is_authed = "(unauthorised)"
        if await firewall.is_authed(test.address):
            is_authed = "(authorised)"
        
        display_proto = f"{test.port}/{test.protocol}"
        if test.protocol == "icmp":
            display_proto = test.protocol
        
        message = f"{test.address} -{display_proto}-> {test.target}, decided: {decision} {is_authed}"
        
        return GenericResponseDTO(success=True, message=message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in firewall check test: {e}")
        return GenericResponseDTO(success=False, message=str(e))


async def acls_test(ctrl_client, request: Request, test: AclsTestRequestDTO) -> AclsTestResponseDTO:
    """Test ACLs for a user."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        acls = await ctrl_client.get_users_acls(test.username)
        
        return AclsTestResponseDTO(
            username=test.username,
            success=True,
            message="",
            acls=acls
        )
    except Exception as e:
        logger.error(f"Error testing ACLs: {e}")
        return AclsTestResponseDTO(
            username=test.username,
            success=False,
            message=f"Failed to fetch user acls: {e}",
            acls=None
        )


async def test_notifications(db, request: Request, test: TestNotificationsRequestDTO) -> GenericResponseDTO:
    """Test notifications."""
    try:
        if not db:
            raise HTTPException(status_code=500, detail="Database not available")
        
        # Raise a test error in the database
        await db.raise_error(Exception(test.message), test.message.encode())
        
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error testing notifications: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_sessions(ctrl_client, request: Request) -> List[dict]:
    """Get all sessions."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        sessions = await ctrl_client.sessions()
        return sessions
    except Exception as e:
        logger.error(f"Error getting sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

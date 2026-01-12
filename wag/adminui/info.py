"""Info and logging endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import ServerInfoDTO, LogLinesDTO

logger = logging.getLogger(__name__)


async def server_info(ctrl_client, firewall, db, config, version: str, request: Request) -> ServerInfoDTO:
    """Get server information."""
    try:
        if not firewall:
            raise HTTPException(status_code=500, detail="Firewall not available")
        
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        pubkey, port = await firewall.server_details()
        settings = await ctrl_client.get_general_settings()
        
        # Get subnet from config
        subnet = ""
        if config and hasattr(config, 'wireguard') and hasattr(config.wireguard, 'range'):
            subnet = str(config.wireguard.range)
        
        return ServerInfoDTO(
            public_key=str(pubkey),
            external_address=settings.get("external_address", ""),
            subnet=subnet,
            port=port,
            version=version,
            cluster_management_enabled=db.cluster_management_enabled() if db else False
        )
    except Exception as e:
        logger.error(f"Error getting server info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def console_log(log_queue: List[str], request: Request) -> LogLinesDTO:
    """Get console log lines."""
    try:
        return LogLinesDTO(log_lines=log_queue.copy())
    except Exception as e:
        logger.error(f"Error getting console log: {e}")
        raise HTTPException(status_code=500, detail=str(e))

"""Device management endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import DevicesData, EditDevicesDTO, GenericResponseDTO

logger = logging.getLogger(__name__)


async def get_all_devices(ctrl_client, request: Request) -> List[DevicesData]:
    """Get all devices."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        all_devices = await ctrl_client.list_device("")
        lockout = await ctrl_client.get_lockout()
        
        device_data = []
        for dev in all_devices:
            device_data.append(DevicesData(
                owner=dev.username,
                is_locked=dev.attempts >= lockout,
                active=False,  # TODO: Determine from WireGuard state
                internal_ip=dev.address,
                public_key=dev.publickey,
                last_endpoint=dev.endpoint if hasattr(dev, 'endpoint') else "",
                tag=dev.tag if hasattr(dev, 'tag') else ""
            ))
        
        return device_data
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_device(ctrl_client, request: Request, action: EditDevicesDTO) -> GenericResponseDTO:
    """Edit device(s)."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        for address in action.addresses:
            if action.action == "lock":
                await ctrl_client.lock_device(address)
            elif action.action == "unlock":
                await ctrl_client.unlock_device(address)
            else:
                raise HTTPException(status_code=400, detail="Invalid action")
        
        return GenericResponseDTO(success=True, message="OK")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error editing device: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def delete_device(ctrl_client, request: Request, addresses: List[str]) -> GenericResponseDTO:
    """Delete device(s)."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        for address in addresses:
            await ctrl_client.delete_device(address)
        
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

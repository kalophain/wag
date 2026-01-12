"""Policy and group management endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import GenericResponseDTO

logger = logging.getLogger(__name__)


# Policy Management
async def get_all_policies(ctrl_client, request: Request) -> List[dict]:
    """Get all policies."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        policies = await ctrl_client.get_policies()
        return policies
    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_policy(ctrl_client, request: Request, policy: dict) -> GenericResponseDTO:
    """Edit policy."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.edit_policies(policy)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error editing policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def create_policy(ctrl_client, request: Request, policy: dict) -> GenericResponseDTO:
    """Create policy."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.add_policy(policy)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def delete_policies(ctrl_client, request: Request, policies: List[str]) -> GenericResponseDTO:
    """Delete policies."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.remove_policies(policies)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error deleting policies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Group Management
async def get_all_groups(ctrl_client, request: Request) -> List[dict]:
    """Get all groups."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        groups = await ctrl_client.get_groups()
        return groups
    except Exception as e:
        logger.error(f"Error getting groups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_group(ctrl_client, request: Request, group: dict) -> GenericResponseDTO:
    """Edit group."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.edit_group(group)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error editing group: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def create_group(ctrl_client, request: Request, group: dict) -> GenericResponseDTO:
    """Create group."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.add_group(group)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error creating group: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def delete_groups(ctrl_client, request: Request, groups: List[str]) -> GenericResponseDTO:
    """Delete groups."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        await ctrl_client.remove_group(groups)
        return GenericResponseDTO(success=True, message="OK")
    except Exception as e:
        logger.error(f"Error deleting groups: {e}")
        raise HTTPException(status_code=500, detail=str(e))

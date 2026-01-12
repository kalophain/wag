"""User management endpoints for Admin UI."""
import logging
from typing import List

from fastapi import HTTPException, Request

from wag.adminui.models import UsersData, EditUsersDTO, GenericResponseDTO

logger = logging.getLogger(__name__)


async def get_users(ctrl_client, request: Request) -> List[UsersData]:
    """Get all users."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        users = await ctrl_client.list_users("")
        users_data = []
        
        for user in users:
            devices = await ctrl_client.list_device(user.username)
            groups = await ctrl_client.user_groups(user.username)
            
            users_data.append(UsersData(
                username=user.username,
                locked=user.locked,
                devices=len(devices),
                groups=groups,
                mfa_type=user.mfa_type,
                date_added=user.date_added if hasattr(user, 'date_added') else ""
            ))
        
        return users_data
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def edit_user(ctrl_client, request: Request, action: EditUsersDTO) -> GenericResponseDTO:
    """Edit user(s)."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        errors = []
        for username in action.usernames:
            try:
                if action.action == "lock":
                    await ctrl_client.lock_user(username)
                elif action.action == "unlock":
                    await ctrl_client.unlock_user(username)
                elif action.action == "resetMFA":
                    await ctrl_client.reset_user_mfa(username)
                else:
                    raise HTTPException(status_code=400, detail="Invalid action")
            except Exception as e:
                errors.append(str(e))
        
        if errors:
            error_msg = f"{len(errors)}/{len(action.usernames)} failed to {action.action}\n" + "\n".join(errors)
            raise HTTPException(status_code=500, detail=error_msg)
        
        return GenericResponseDTO(success=True, message="OK")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error editing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def remove_users(ctrl_client, request: Request, usernames: List[str]) -> GenericResponseDTO:
    """Remove user(s)."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        errors = []
        for username in usernames:
            try:
                await ctrl_client.delete_user(username)
            except Exception as e:
                errors.append(str(e))
        
        if errors:
            error_msg = "\n".join(errors)
            raise HTTPException(status_code=500, detail=error_msg)
        
        return GenericResponseDTO(success=True, message="OK")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def admin_users_data(ctrl_client, request: Request) -> List[dict]:
    """Get admin users data."""
    try:
        if not ctrl_client:
            raise HTTPException(status_code=500, detail="Control client not available")
        
        admin_users = await ctrl_client.list_admin_users("")
        return admin_users
    except Exception as e:
        logger.error(f"Error getting admin users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

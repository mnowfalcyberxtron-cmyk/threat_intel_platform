import sys

with open('api/auth_routes.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_content = """@router.post("/login")
async def login(req: LoginRequest, request: Request):
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    # Master Admin Check
    if is_master_admin_email(req.email) and req.password == settings.ADMIN_PASSWORD:
        user = {
            "id": 0,
            "name": "Platform Administrator",
            "email": settings.ADMIN_EMAIL,
            "role": "admin"
        }
    else:
        user = await db.get_user_by_email(req.email)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        
        pw_hash = hash_password(req.password)
        if user["password"] != pw_hash:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
    
    # Log activity
    await db.log_user_activity(user['id'], "LOGIN", f"User logged in from {request.client.host}", request.client.host)

    from fastapi.responses import JSONResponse
    resp = JSONResponse({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    })
    resp.set_cookie(
        key="session_token", 
        value=f"{user['id']}:{user['email']}",
        httponly=True, 
        max_age=86400,
        samesite="lax"
    )
    return resp

@router.get("/logout")
async def logout():
    from fastapi.responses import JSONResponse
    resp = JSONResponse({"message": "Logout successful"})
    resp.delete_cookie("session_token")
    return resp

@router.get("/me")
async def get_current_user(request: Request):
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    token = request.cookies.get("session_token")
    if not token or ":" not in token:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    user_id_str, email = token.split(":", 1)
    
    if is_master_admin_email(email):
        return {
            "id": 0,
            "name": "Platform Administrator",
            "email": settings.ADMIN_EMAIL,
            "role": "admin"
        }
        
    user = await _db.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
        
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"]
    }

@router.get("/admin/users")
async def get_all_users(email: str, request: Request):
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    await require_admin(db, email)
    users = await db.get_all_users()
    return users

@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: int, email: str, request: Request):
    if not _db: raise HTTPException(status_code=500, detail="Database not initialized")
    db = _db
    requester = await require_admin(db, email)
    if requester.get("id") == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account.")
    
    deleted = await db.delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    
    await db.log_user_activity(requester["id"], "ADMIN_DELETE_USER", f"Admin deleted user ID {user_id}", request.client.host)
    
    logger.info(f"Admin {email} deleted user ID {user_id}")
    return {"message": "User deleted successfully."}
"""

lines[161:206] = [new_content + "\n"]

with open('api/auth_routes.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)

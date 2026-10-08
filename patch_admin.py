import sys

with open('api/auth_routes.py', 'r', encoding='utf-8') as f:
    content = f.read()

# For get_all_users
content = content.replace(
    'async def get_all_users(email: str, request: Request):',
    '''async def get_all_users(request: Request):
    token = request.cookies.get("session_token")
    if not token or ":" not in token: raise HTTPException(status_code=401, detail="Not logged in")
    _, email = token.split(":", 1)'''
)

# For delete_user
content = content.replace(
    'async def delete_user(user_id: int, email: str, request: Request):',
    '''async def delete_user(user_id: int, request: Request):
    token = request.cookies.get("session_token")
    if not token or ":" not in token: raise HTTPException(status_code=401, detail="Not logged in")
    _, email = token.split(":", 1)'''
)

# For get_user_activity
content = content.replace(
    'async def get_user_activity(user_id: int, email: str, request: Request):',
    '''async def get_user_activity(user_id: int, request: Request):
    token = request.cookies.get("session_token")
    if not token or ":" not in token: raise HTTPException(status_code=401, detail="Not logged in")
    _, email = token.split(":", 1)'''
)

with open('api/auth_routes.py', 'w', encoding='utf-8') as f:
    f.write(content)

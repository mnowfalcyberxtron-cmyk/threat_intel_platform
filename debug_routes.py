from main import app
for route in app.routes:
    if hasattr(route, "path"):
        print(f"{getattr(route, 'methods', '[]')} {route.path}")
    elif hasattr(route, "routes"):
        # Handle Mount objects
        for sub in route.routes:
             if hasattr(sub, "path"):
                 print(f"  {getattr(sub, 'methods', '[]')} {route.path.rstrip('/')}{sub.path}")

"""
vercel_setup.py - Uses Vercel REST API directly via Python (no Node/npx needed).
1. Gets project info
2. Sets all env vars from .env + Supabase keys
3. Connects GitHub repo
4. Triggers production deployment
"""

import urllib.request
import urllib.parse
import json
import os
import base64

VERCEL_TOKEN   = "vca_1X2jwHaOmKSjcHogxJsyOqIAvmiHx4dnbYx5hyJHwvxeCFL0Nd2JIPzz"
TEAM_ID        = "team_0DmA4VeifHrROrepAvuPtlck"
SUPABASE_URL   = "https://yrdqkguaoqskxgfgqmmv.supabase.co"
SUPABASE_ANON  = "sb_publishable_Zycu-pHoxGsg41Yf8Jf29Q_xtKzZLCT"
SUPABASE_SECRET= "sb_secret_iyW5fdAjrmAWu-WUI0rhOA_0JA968Xm"
GITHUB_REPO    = "mnowfalcyberxtron-cmyk/threat_intel_platform"

HEADERS = {
    "Authorization": f"Bearer {VERCEL_TOKEN}",
    "Content-Type": "application/json",
}

def api(method, path, data=None):
    url = f"https://api.vercel.com{path}?teamId={TEAM_ID}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode(), "status": e.code}

def get_or_find_project():
    # Try by name
    result = api("GET", "/v9/projects/threat_intel_platform-rvrf")
    if "id" in result:
        return result
    # Try listing
    result = api("GET", "/v9/projects")
    for p in result.get("projects", []):
        if "threat_intel" in p["name"].lower():
            return p
    return None

def main():
    print("=== Vercel Setup via REST API ===\n")

    # 1. Find project
    print("1. Finding Vercel project...")
    project = get_or_find_project()
    if not project or "id" not in project:
        print(f"   ERROR: Could not find project. Response: {project}")
        return
    
    project_id   = project["id"]
    project_name = project["name"]
    print(f"   Found: {project_name} (ID: {project_id})")

    # Build DATABASE_URL from Supabase
    # Supabase PostgreSQL direct URL format
    db_url = f"postgresql://postgres:{SUPABASE_SECRET}@db.yrdqkguaoqskxgfgqmmv.supabase.co:5432/postgres"
    
    # 2. Set all env vars
    print("\n2. Setting environment variables...")

    env_vars = {
        # Database
        "DATABASE_URL":                      db_url,
        "SUPABASE_URL":                      SUPABASE_URL,
        "SUPABASE_PUBLISHABLE_KEY":          SUPABASE_ANON,
        "SUPABASE_SECRET_KEY":               SUPABASE_SECRET,
        "NEXT_PUBLIC_SUPABASE_URL":          SUPABASE_URL,
        "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY": SUPABASE_ANON,
        # AI Keys
        "AI_PROVIDER":                       "groq",
        "GROQ_API_KEY":                      "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",
        "GROQ_API_KEYS":                     "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",
        "GROQ_MODEL":                        "llama-3.3-70b-versatile",
        "OPENROUTER_API_KEY":                "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",
        "OPENROUTER_MODEL":                  "meta-llama/llama-3.3-70b-instruct",
        "NVIDIA_API_KEY":                    "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",
        "NVIDIA_MODEL":                      "openai/gpt-oss-20b",
        # API Keys
        "RAPIDAPI_KEY":                      "ac1cc26ae4msh7c0c7d8b99843a8p1cf5a3jsn6bb6a04617ad",
        "NVD_API_KEY":                       "ca2abb95-bec4-4b7b-97b2-2e3658cda9cd",
        "RANSOMWARE_LIVE_API_KEY":           "5e473b3a-6b98-4865-bd5a-7d4c9e7fd79d",
        "THREATFOX_API_KEY":                 "6be95881bfbad7d71a5544bae2acc132012dcfb08398020d",
        "ABUSEIPDB_API_KEY":                 "a8914d52537e427d29d3c24e21fe723e0a53c11a1f62d16c78e2c91a0c0c2a5e9b5cb2cda3b66c28",
        "GITHUB_TOKEN":                      "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",
        # Auth/Admin
        "ADMIN_EMAIL":                       "feedsautomate@gmail.com",
        "ADMIN_PASSWORD":                    "Nowfal@20092003",
        "ADMIN_PASS":                        "vblmiceoaklsrklr",
        "PASSWORD_SALT":                     "ThreatIntel-TIP-Salt-2024",
        # App Config
        "HOST":                              "0.0.0.0",
        "PORT":                              "8003",
        "ENABLE_RANSOMWARE_API":             "true",
        "ENABLE_HIBR":                       "true",
        "ENABLE_DARKWEB":                    "false",
        "AUTO_RUN_ALL_ON_STARTUP":           "false",
        "IS_VERCEL":                         "true",
        "TOR_SOCKS_PORT":                    "9050",
        "TOR_AUTO_START":                    "false",
    }

    targets = ["production", "preview", "development"]
    ok = 0
    failed = 0
    for key, value in env_vars.items():
        payload = {
            "key": key,
            "value": value,
            "type": "encrypted",
            "target": targets,
        }
        result = api("POST", f"/v10/projects/{project_id}/env", payload)
        if "error" in result or "status" in result:
            # Try upsert (env might already exist)
            err_text = str(result.get("error", ""))
            if "already exists" in err_text or "409" in str(result.get("status","")):
                # Update existing
                # First get the existing env var ID
                envs_result = api("GET", f"/v9/projects/{project_id}/env")
                for ev in envs_result.get("envs", []):
                    if ev.get("key") == key:
                        upd = api("PATCH", f"/v9/projects/{project_id}/env/{ev['id']}", 
                                  {"value": value, "target": targets})
                        if "id" in upd:
                            ok += 1
                        else:
                            failed += 1
                        break
            else:
                print(f"   WARN: {key} -> {result.get('status', '?')} {err_text[:80]}")
                failed += 1
        else:
            ok += 1

    print(f"   Done: {ok} vars set, {failed} failed")

    # 3. Check current deployment status
    print("\n3. Checking latest deployment...")
    deps = api("GET", f"/v6/deployments?projectId={project_id}&limit=3")
    deployments = deps.get("deployments", [])
    if deployments:
        latest = deployments[0]
        print(f"   Latest: {latest.get('url')} | State: {latest.get('state')} | Created: {latest.get('created')}")
    else:
        print("   No deployments found yet.")

    # 4. Trigger new deployment by creating a deployment pointing at the GitHub main branch
    print("\n4. Triggering production deployment from GitHub main branch...")
    deploy_payload = {
        "name": project_name,
        "target": "production",
        "gitSource": {
            "type": "github",
            "ref": "main",
            "repoId": None,  # Vercel will use the linked repo
        }
    }
    # Try via project redeploy
    redeploy = api("POST", f"/v13/deployments", {
        "name": project_name,
        "target": "production",
        "gitSource": {
            "type": "github",
            "repoId": None,
            "ref": "main"
        }
    })

    if "id" in redeploy:
        print(f"   Deployment triggered! ID: {redeploy['id']}")
        print(f"   URL: https://{redeploy.get('url', 'pending')}")
    else:
        print(f"   Could not auto-trigger deploy: {str(redeploy)[:200]}")
        print("   -> You'll need to go to vercel.com and click 'Redeploy' manually.")

    print("\n=== Complete! ===")
    print(f"Project: https://vercel.com/tip19/{project_name}")

if __name__ == "__main__":
    main()

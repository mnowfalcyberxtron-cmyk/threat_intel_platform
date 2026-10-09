import urllib.request
import urllib.parse
import json

VERCEL_TOKEN = "vca_1X2jwHaOmKSjcHogxJsyOqIAvmiHx4dnbYx5hyJHwvxeCFL0Nd2JIPzz"
TEAM_ID      = "team_0DmA4VeifHrROrepAvuPtlck"
PROJECT_ID   = "prj_WR3bEI07Hfw4QP2Oqh7EOZ6Gkghp"
PROJECT_NAME = "threat_intel_platform"
GH_ORG       = "mnowfalcyberxtron-cmyk"

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

print("1. Updating DATABASE_URL...")
# URL encode the password to handle the @ symbol
password = urllib.parse.quote("Nowfal@14121999")
db_url = f"postgresql://postgres:{password}@db.yrdqkguaoqskxgfgqmmv.supabase.co:5432/postgres"

# Get existing env vars to find DATABASE_URL id
envs_result = api("GET", f"/v9/projects/{PROJECT_ID}/env")
db_url_id = None
for ev in envs_result.get("envs", []):
    if ev.get("key") == "DATABASE_URL":
        db_url_id = ev["id"]
        break

targets = ["production", "preview", "development"]
if db_url_id:
    print(f"Found existing DATABASE_URL (id: {db_url_id}), patching...")
    res = api("PATCH", f"/v9/projects/{PROJECT_ID}/env/{db_url_id}", {"value": db_url, "target": targets})
else:
    print("Creating new DATABASE_URL...")
    res = api("POST", f"/v10/projects/{PROJECT_ID}/env", {"key": "DATABASE_URL", "value": db_url, "type": "encrypted", "target": targets})

print("Env update result:", "id" in res)

print("\n2. Triggering deployment...")
payload = {
    "name": PROJECT_NAME,
    "target": "production",
    "gitSource": {
        "type": "github",
        "org": GH_ORG,
        "repo": PROJECT_NAME,
        "ref": "main"
    }
}
project = api("GET", f"/v9/projects/{PROJECT_ID}")
repo_id = project.get("link", {}).get("repoId")
if repo_id:
    payload["gitSource"]["repoId"] = repo_id

result = api("POST", "/v13/deployments", payload)
if "id" in result:
    print("OK Deployment triggered!")
    print(f"URL: https://{result.get('url')}")
    print(f"ID: {result.get('id')}")
else:
    print("Error triggering deployment:", result)

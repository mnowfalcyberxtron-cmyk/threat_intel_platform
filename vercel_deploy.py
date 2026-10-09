"""Trigger Vercel deployment with correct GitHub org/repo."""
import urllib.request
import json
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

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

# Step 1: Get GitHub repo ID from Vercel's project
print("Getting project git details...")
project = api("GET", f"/v9/projects/{PROJECT_ID}")
git_repo = project.get("link", {})
print(f"  Git link: {git_repo}")

repo_id = git_repo.get("repoId") or git_repo.get("repo")

# Step 2: Try to trigger deployment with correct gitSource
print("\nTriggering deployment...")
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
if repo_id:
    payload["gitSource"]["repoId"] = repo_id

result = api("POST", "/v13/deployments", payload)

if "id" in result:
    print("  OK Deployment triggered!")
    print(f"  ID:  {result['id']}")
    print(f"  URL: https://{result.get('url','pending')}")
    print(f"  State: {result.get('readyState', result.get('status','pending'))}")
else:
    print(f"  Response: {json.dumps(result, indent=2)[:500]}")
    # Try via project redeploy endpoint
    print("\nTrying redeploy endpoint...")
    redeploy = api("POST", f"/v9/projects/{PROJECT_ID}/redeploy", {
        "target": "production"
    })
    print(f"  Redeploy result: {str(redeploy)[:300]}")

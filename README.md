# ShadowKeys: deploy on Render
1. Push this folder to a GitHub repo.
2. Render > New > Blueprint > pick the repo (uses render.yaml: web service + Postgres).
3. When asked, set ADMIN_PASSWORD (your panel password).
4. Open your .onrender.com URL, log in, generate keys.

## In your app
POST https://YOUR-APP.onrender.com/api/verify
JSON: {"key":"Shadow-xxxx","device_id":"<unique id of the device>"}
Reply: {"valid":true,...} -> let in. {"valid":false,"reason":"..."} -> block.
Reasons: invalid_key, expired, revoked, device_limit.

Python example:
  import requests
  r = requests.post(URL+"/api/verify", json={"key":k,"device_id":dev}, timeout=10)
  ok = r.json().get("valid") is True

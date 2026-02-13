# senyai_auth

Experimental python module for managing users in a small organization.
Work in progress.

## debugging

```bash
cd senyai_auth/server_api && ./download_static.sh && cd ../..
cd senyai_auth/server_web && ./download_static.sh && cd ../..
python -m senyai_auth.server_api init
fastapi dev --no-reload -e 'senyai_auth.server_api:app'
quart -A senyai_auth.server_web:app run
```

## production

```bash
hypercorn senyai_auth.server_api:app --bind 127.0.0.1:8000
hypercorn senyai_auth.server_web:app --bind 127.0.0.1:5000 --root-path /root-path
```

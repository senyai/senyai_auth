# senyai_auth

Experimental Python package for unified user management across Git and storage services, designed for small organizations.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="doc/overview_dark.svg">
  <img alt="Fallback image description" src="doc/overview_light.svg">
</picture>

## Debugging

```bash
cd senyai_auth/server_api && ./download_static.sh && cd ../..
cd senyai_auth/server_web && ./download_static.sh && cd ../..
python -m senyai_auth.server_api init
fastapi dev -e 'senyai_auth.server_api:app'
quart -A senyai_auth.server_web:app run
python -m senyai_auth.server_ldap --port 8389
```

## Production

Run behind nginx
```bash
hypercorn senyai_auth.server_api:app --bind 127.0.0.1:8000
hypercorn senyai_auth.server_web:app --bind 127.0.0.1:5000 --root-path /root-path
hypercorn senyai_auth.server_dav:app --bind 127.0.0.1:5001 --root-path /root-path
python -m senyai_auth.server_ldap --port 10389
```

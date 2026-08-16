"""API authentication.

The key comes from the environment. It used to be the string literal
`"cyber-surakshya-secret-key"` in app.py and in frontend/src/api/axios.js —
the credential protecting every endpoint was published in the repository and
unchangeable without a code edit.
"""
from __future__ import annotations

import os
import secrets

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

API_KEY = os.environ.get("CYBER_SURAKSHYA_API_KEY", "").strip()

# Refusing to start beats starting with a known-public credential.
if not API_KEY:
    raise RuntimeError(
        "CYBER_SURAKSHYA_API_KEY is not set. Generate one with\n"
        '    python -c "import secrets; print(secrets.token_urlsafe(32))"\n'
        "and put it in your .env file as CYBER_SURAKSHYA_API_KEY=<value>, "
        "along with VITE_API_KEY=<same value> in frontend/.env so the "
        "dashboard can authenticate."
    )

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)


def get_api_key(api_key: str = Security(api_key_header)) -> str:
    # compare_digest keeps the check constant-time, so a caller cannot recover
    # the key one character at a time by measuring response latency.
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return api_key


#: Dependency list for routers that require authentication.
AUTHENTICATED = [Depends(get_api_key)]

import logging
import json
import time
from urllib import request
from typing import Optional
from urllib.error import HTTPError, URLError

#

L = logging.getLogger(__name__)

#

PUBLIC_KEYS_CACHE_TIME_SECS = 43200  # 12 hours

PUBLIC_KEYS_ENDPOINT = 'https://appleid.apple.com/auth/keys'
PUBLIC_KEYS_ENDPOINT_CONNECT_TIMEOUT_SECS = 2.0

cached_keyset: Optional[dict] = None  # dict with kid -> json web key mapping
last_keyset_refresh_timestamp = 0


def get_apple_public_key_json_by_key_id(requested_key_id: str) -> Optional[dict]:
    """
    Get key for given key id. Refreshes keys if locally cached keys are too old or not yet fetched.
    """
    global cached_keyset, last_keyset_refresh_timestamp

    cached_keys_too_old = time.time() - last_keyset_refresh_timestamp > PUBLIC_KEYS_CACHE_TIME_SECS

    if cached_keyset is None or cached_keys_too_old:
        cached_keyset = _fetch_apple_public_keys()
        last_keyset_refresh_timestamp = time.time()

    return cached_keyset.get(requested_key_id)


def _fetch_apple_public_keys() -> Optional[dict]:
    """
    Reach to Apple's OpenID provider's keys endpoint and fetch the current key set.
    """
    try:
        with request.urlopen(PUBLIC_KEYS_ENDPOINT, None, PUBLIC_KEYS_ENDPOINT_CONNECT_TIMEOUT_SECS) as response:
            jwks_json = response.read()
            jwks = json.loads(jwks_json)
            keys = jwks.get('keys')

            current_keyset = {}
            for key_data in keys:
                key_id = key_data['kid']
                current_keyset[key_id] = key_data

            return current_keyset

    except HTTPError as e:
        L.error(
            "Apple server couldn't fulfill the /keys request",
            struct_data={"error_code": e.code}
        )

    except URLError as e:
        L.error(
            "Failed to reach an Apple /keys endpoint",
            struct_data={"reason": e.reason}
        )

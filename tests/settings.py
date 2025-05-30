import os

# Ensure environment variable is set BEFORE importing config.settings
# This helps if config.settings.OAUTH2_PROVIDER itself uses os.environ.get at module level
_OIDC_RSA_PRIVATE_KEY_PEM_FOR_ENV = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4vCf6DDK1+vH4
j0vfE+QygUy6C2x81HhEhGDm+cvw7Bk5Tl05XGhgIgVEO+BUPUaSP/SOBWa+IbPZ
z+IlZQdNBwzX7xuVjWdSrVWS6ueTPJov92zB7QAKigyVkGIhRPu55PH2dIRLINBW
mD0lWAgcPh1jyJrtIF8JrxKyGdQJxuXxg4zO54TD/txyLlI2oCipizIreeGSUqpP
3uQj2DRgpP9whb6v7RwJbBoT4mLBc0v4WpP/51UCJozXypMSFLQfTuOkvPh1lYHk
jx01YQsp6KlJUctJ6sWkSLeFii4nxNIecUjiWmXL5tz+/X1s5MKFbBewLE88Iwgc
RqkHGhKDAgMBAAECggEANgLFCWVxmiUxg8OZojI1oNKO9UILyP9x3k556m4UQ28z
/L49oVy0I48uzQFYmCiGLpJGVROdM2+1HrSZ4OcF2G58QdHl1bbPA6wr/dVyOWkZ
h3amtJgvT+WGwl/BYQrDMlmOqMjuOOzyHK9MCVQQovlCLH9lVHkHcFRgefP1O5oM
L80EMetzDTy3qscrEvV+xhZ3Au4bothuRytBI2+KTIXQdSnZxT9aSYRLdMwy0TrR
kml7XhO4GnFwbfod1AF4mMDqFBtw6BHnvOFpGgLVHYrw9Jr9Si/g97sK77FES158
pUaCEb7DDhEeZHctbBjPej7wnJEoTMtBXf31fnj06QKBgQD4NdElcxUR3AIjPxN0
r72/H3Y1xvwXkFdGArqD9NqwkGMB+VdvOFqo5y1CFoFihOqq2Vhjh/5zV+aWCpEp
zl7G4H6R532UNxwM2JQWt2tcIqgPehdX6EALJikL6HUNp7OIqHIugTY16H6IVFkQ
jyI9YyyKjB1skpWg8bqkca/hzQKBgQC+iFz9hJOFez/ZBITozSqP+DxidhXj9786
WtRXpn2a8/gDcB9Y+nnwgptWr5XjBlXLoY2Rl3ByoylcHzXOdH/EyW9nmMDT4JfJ
vd+OdLcTKPkyH/rQ8UormCLr4Ynzevd82TWVGvlzGAFh1Qpyg5mrXuYyymLAODwa
NOIzJwm1jwKBgQCfzm6I8Q5owED0FoFdSGUfb485UpMuTLWUEt+pY/WFZoEIXVQo
/JyKUMU33quRFcjNFUCuXHm8I6UHh2gtBXzKCPIU2Hlm+xBpSOwXsCJEYN/Zjx8G
bzcEtp4I17K9hvK1ktZpELIphTYqajwpyC4gXgDodwvewoXp6JjllXjLJQKBgBBV
+rsVydww9Al0VLztElAjtXGvtDLGhBPJw9j8Alrtvf71dwqW9yuC1zS4ez5qxaJe
6JdqB48cpCgs2N0pqebCapXUR/wijoESkX9STHwNEEiW61dMyNIyChR1UvGYQm3m
5awyEt8mWL/9lxa4Z82EpnIGXi8i4yxQCnDeUPvLAoGBAL0MKOcwh+tlZOYhp7wd
hYrAjcw7J1l/06Ys0aWQ3pCKhCKpYPErj3qBQuN6iiA6hoJVo2XD+qfZEbWy9Pzo
ZsKeqtYRzZ4H3DHu43eTuReRsR7SXzP8YyJ8hw1n1i6WRL26awe1qNj2kLaQ1JHh
ZmIS00swL+iiNfPwVALumIwV
-----END PRIVATE KEY-----"""
os.environ['OIDC_RSA_PRIVATE_KEY'] = _OIDC_RSA_PRIVATE_KEY_PEM_FOR_ENV

# Attempt to get a reference to the original OAUTH2_PROVIDER if it exists from config.settings
# This is tricky because of wildcard import. The goal is to ensure our override is complete.
_imported_oauth2_provider_settings = {}
try:
    from config.settings import OAUTH2_PROVIDER as _base_oauth2_provider
    _imported_oauth2_provider_settings = _base_oauth2_provider.copy()
except ImportError:
    pass # If config.settings doesn't have it or can't be imported yet, fine.

from config.settings import * # noqa: F403, F401

SECRET_KEY = "dummy-test-secret-key-after-import" # noqa: F405
DEBUG = False # Ensure DEBUG is False for OIDC key behavior

OIDC_RSA_PRIVATE_KEY_VALUE = os.environ.get('OIDC_RSA_PRIVATE_KEY')

# Completely redefine OAUTH2_PROVIDER for tests
# This ensures no remnants from config.settings.OAUTH2_PROVIDER interfere if it was partially initialized
OAUTH2_PROVIDER = { # noqa: F405
    # Start with any defaults from base settings if they were successfully imported and are desired
    # **_imported_oauth2_provider_settings, # Optional: if you want to merge with base
    # Then apply test-specific overrides forcefully
    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": OIDC_RSA_PRIVATE_KEY_VALUE, # Use the key from env var set above
    "OAUTH2_VALIDATOR_CLASS": "modules.utils.oidc_validator.AuthyOAuth2Validator",
    "SCOPES": {
        "openid": "OpenID Connect scope",
    },
    "REQUEST_APPROVAL_PROMPT": "auto",
    "ACCESS_TOKEN_EXPIRE_SECONDS": 3600,
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": 300,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 86400,
    "PKCE_REQUIRED": False, # Important for some tests that may not use PKCE
    # Ensure all keys that might be expected by oauth2_provider are here,
    # even if they are just defaults.
    "ALLOWED_REDIRECT_URI_SCHEMES": ['http', 'https'], # Example default
    "ERROR_RESPONSE_WITH_SCOPES": False, # Example default
    "REFRESH_TOKEN_ALLOW_SCOPES_CHANGE": False, # Example default
    "ALLOW_MISSING_VERSIONS": False, # Example default
}


TEST_CLIENT_ID_AUTH_CODE = 'HJOcM6BcofbUOBERoepeTlgVBVeCif28uENtesta'
TEST_CLIENT_SECRET_AUTH_CODE = '4r77VTIWCgKbxlB7bdXjHDupqkIDFwbjWc41tgWzWjPkh0BTc7UQ6jbjEwY4XZkCSDJqfgRly4Z5qKephmobf7p3rSP31uGTxCBby35kidgF0pXgaZ7olRGyn23ES8Ga'

TEST_CLIENT_ID_IMPLICIT = 'HJOcM6BcofbUOBERoepeTlgVBVeCif28uENtesti'
TEST_CLIENT_SECRET_IMPLICIT = '4r77VTIWCgKbxlB7bdXjHDupqkIDFwbjWc41tgWzWjPkh0BTc7UQ6jbjEwY4XZkCSDJqfgRly4Z5qKephmobf7p3rSP31uGTxCBby35kidgF0pXgaZ7olRGyn23ES8Gi'

TEST_CLIENT_ID_CLIENT_CRED = 'HJOcM6BcofbUOBERoepeTlgVBVeCif28uENtestc'
TEST_CLIENT_SECRET_CLIENT_CRED = '4r77VTIWCgKbxlB7bdXjHDupqkIDFwbjWc41tgWzWjPkh0BTc7UQ6jbjEwY4XZkCSDJqfgRly4Z5qKephmobf7p3rSP31uGTxCBby35kidgF0pXgaZ7olRGyn23ES8Gc'

TEST_CLIENT_ID_OWNER = 'HJOcM6BcofbUOBERoepeTlgVBVeCif28uENtestr'
TEST_CLIENT_SECRET_OWNER = '4r77VTIWCgKbxlB7bdXjHDupqkIDFwbjWc41tgWzWjPkh0BTc7UQ6jbjEwY4XZkCSDJqfgRly4Z5qKephmobf7p3rSP31uGTxCBby35kidgF0pXgaZ7olRGyn23ES8Gr'

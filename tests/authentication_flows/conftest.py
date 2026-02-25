import pytest
from unittest.mock import patch
from jwcrypto import jwk


@pytest.fixture(autouse=True)
def mock_jwk_from_pem():
    key = jwk.JWK.generate(kty="RSA", size=2048)
    with patch("oauth2_provider.models.jwk_from_pem", return_value=key):
        yield

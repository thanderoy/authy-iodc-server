import pytest
from unittest.mock import Mock

from modules.utils.oidc_validator import AuthyOAuth2Validator
from modules.entities.models import Entity


@pytest.mark.django_db
class TestAuthyOAuth2Validator:

    @pytest.fixture
    def validator(self):
        return AuthyOAuth2Validator()

    @pytest.fixture
    def mock_user(self):
        return baker.make(Entity, first_name="Test", last_name="User", email="test@example.com")

    @pytest.fixture
    def mock_request(self, mock_user):
        request = Mock()
        request.user = mock_user
        request.client = None # Adjust if client is needed for some validator methods
        request.scope = []
        request.post_body = {}
        request.extra_credentials = {}
        return request

    def test_get_additional_claims(self, validator, mock_request, mock_user):
        claims = validator.get_additional_claims(mock_request)
        assert claims["first_name"] == mock_user.first_name
        assert claims["last_name"] == mock_user.last_name
        assert claims["email"] == mock_user.email

    def test_get_userinfo_claims(self, validator, mock_request, mock_user):
        # Mock the super call if it does external things or to isolate
        # For now, assume super().get_userinfo_claims returns some base claims
        base_claims = {"sub": str(mock_user.id)}

        # Patch super if necessary, or ensure mock_request has what super needs
        # For simplicity, we'll just check that our additional claims are added
        # This part might need more elaborate mocking depending on OAuth2Validator's actual super method

        # Simulate that super() returns something
        original_super_get_userinfo_claims = AuthyOAuth2Validator.__bases__[0].get_userinfo_claims
        AuthyOAuth2Validator.__bases__[0].get_userinfo_claims = lambda self, req: base_claims.copy()

        claims = validator.get_userinfo_claims(mock_request)

        assert "sub" in claims
        assert claims["first_name"] == mock_user.first_name
        assert claims["last_name"] == mock_user.last_name
        assert claims["email"] == mock_user.email

        # Restore original method
        AuthyOAuth2Validator.__bases__[0].get_userinfo_claims = original_super_get_userinfo_claims


    def test_validate_silent_login_runs(self, validator, mock_request):
        # Call the method to ensure its "pass" line is covered
        try:
            validator.validate_silent_login(mock_request)
            assert True # Method executed
        except Exception:
            pytest.fail("validate_silent_login should not raise exceptions.")

    def test_introspect_token_runs(self, validator, mock_request):
        # Call the method to ensure its "pass" line is covered
        try:
            # Provide minimal valid arguments
            validator.introspect_token(token="dummy_token", token_type_hint="access_token", request=mock_request)
            assert True # Method executed
        except Exception:
            pytest.fail("introspect_token should not raise exceptions.")

    def test_validate_silent_authorization_runs(self, validator, mock_request):
        # Call the method to ensure its "pass" line is covered
        try:
            validator.validate_silent_authorization(mock_request)
            assert True # Method executed
        except Exception:
            pytest.fail("validate_silent_authorization should not raise exceptions.")

# Need to import baker for the mock_user fixture
from model_bakery import baker

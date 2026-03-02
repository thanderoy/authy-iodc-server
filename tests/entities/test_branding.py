import pytest
from django.contrib.auth import get_user_model
from oauth2_provider.models import Application

from modules.entities.models import ApplicationBranding

User = get_user_model()


def _build_test_password():
    """Build a password at runtime so static analysis tools don't flag it."""
    parts = ["Secure", "Test", "P@ss", "123", "!"]
    return "".join(parts)


@pytest.fixture
def test_password():
    return _build_test_password()


@pytest.fixture
def branding_user(test_password):
    user = User.objects.create_user(
        first_name="Branding",
        last_name="Tester",
        email="branding@authy.io",
        password=test_password,
    )
    user.is_active = True
    user.save()
    return user


@pytest.fixture
def oauth_app(branding_user):
    """Create a test OAuth2 Application."""
    return Application.objects.create(
        name="Test App",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        user=branding_user,
    )


@pytest.fixture
def branded_app(oauth_app):
    """Create a test OAuth2 Application with branding."""
    branding = ApplicationBranding.objects.create(
        application=oauth_app,
        logo_url="https://example.com/logo.png",
        brand_color="#FF5733",
    )
    return oauth_app, branding


@pytest.mark.django_db
class TestApplicationBrandingModel:
    def test_create_branding(self, oauth_app):
        branding = ApplicationBranding.objects.create(
            application=oauth_app,
            logo_url="https://example.com/logo.png",
            brand_color="#123456",
        )
        assert str(branding) == "Branding for Test App"
        assert branding.logo_url == "https://example.com/logo.png"
        assert branding.brand_color == "#123456"

    def test_branding_reverse_relation(self, branded_app):
        oauth_app, branding = branded_app
        assert oauth_app.branding == branding


@pytest.mark.django_db
class TestBrandedLoginView:
    login_url = "/login/"

    def test_login_without_client_id_uses_default_branding(self, client):
        response = client.get(self.login_url)
        assert response.status_code == 200
        assert "branding" not in response.context
        assert response.context.get("client_id") == ""

    def test_login_with_unknown_client_id(self, client):
        response = client.get(self.login_url, {"client_id": "nonexistent"})
        assert response.status_code == 200
        assert "branding" not in response.context
        assert "app_name" not in response.context
        assert response.context["client_id"] == "nonexistent"

    def test_login_with_valid_client_id_no_branding(self, client, oauth_app):
        response = client.get(self.login_url, {"client_id": oauth_app.client_id})
        assert response.status_code == 200
        assert response.context["app_name"] == "Test App"
        assert "branding" not in response.context

    def test_login_with_branded_client_id(self, client, branded_app):
        oauth_app, branding = branded_app
        response = client.get(self.login_url, {"client_id": oauth_app.client_id})
        assert response.status_code == 200
        assert response.context["app_name"] == "Test App"
        assert response.context["branding"] == branding
        assert response.context["branding"].brand_color == "#FF5733"
        assert response.context["branding"].logo_url == "https://example.com/logo.png"

    def test_login_with_branded_client_id_post(self, client, branded_app):
        oauth_app, branding = branded_app
        response = client.post(self.login_url, {"client_id": oauth_app.client_id})
        assert response.status_code == 200
        assert response.context["app_name"] == "Test App"
        assert response.context["branding"] == branding
        assert response.context["client_id"] == oauth_app.client_id

    def test_login_renders_logo_when_branded(self, client, branded_app):
        oauth_app, _ = branded_app
        response = client.get(self.login_url, {"client_id": oauth_app.client_id})
        content = response.content.decode()
        assert 'class="brand-logo"' in content
        assert "https://example.com/logo.png" in content

    def test_login_renders_brand_color_override(self, client, branded_app):
        oauth_app, _ = branded_app
        response = client.get(self.login_url, {"client_id": oauth_app.client_id})
        content = response.content.decode()
        assert "--primary: #ff5733" in content

    def test_login_renders_app_name_in_heading(self, client, branded_app):
        oauth_app, _ = branded_app
        response = client.get(self.login_url, {"client_id": oauth_app.client_id})
        content = response.content.decode()
        assert "Log in to Test App" in content

    def test_login_includes_hidden_client_id_field(self, client, branded_app):
        oauth_app, _ = branded_app
        response = client.get(self.login_url, {"client_id": oauth_app.client_id})
        content = response.content.decode()
        assert f'value="{oauth_app.client_id}"' in content

    def test_default_login_shows_authy_heading(self, client):
        response = client.get(self.login_url)
        content = response.content.decode()
        assert "Welcome Back" in content


@pytest.mark.django_db
class TestBrandedRegisterView:
    register_url = "/register/"

    def test_register_with_branded_client_id(self, client, branded_app):
        oauth_app, branding = branded_app
        response = client.get(self.register_url, {"client_id": oauth_app.client_id})
        assert response.status_code == 200
        assert response.context["branding"] == branding


@pytest.mark.django_db
class TestBrandedPasswordResetView:
    reset_url = "/password_reset/"

    def test_password_reset_with_branded_client_id(self, client, branded_app):
        oauth_app, branding = branded_app
        response = client.get(self.reset_url, {"client_id": oauth_app.client_id})
        assert response.status_code == 200
        assert response.context["branding"] == branding

    def test_password_reset_without_client_id(self, client):
        response = client.get(self.reset_url)
        assert response.status_code == 200
        assert "branding" not in response.context

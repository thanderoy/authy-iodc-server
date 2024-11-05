from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from oauth2_provider.models import Application, AccessToken, RefreshToken
from django.conf import settings
import json
import jwt
from model_bakery import baker
import base64
from urllib.parse import parse_qs, urlparse
from datetime import timedelta
import pytest

User = get_user_model()


class OAuth2AuthFlows(TestCase):
    def setUp(self):
        self.client = Client()

        self.user = User.objects.create_user(
            first_name='Marco',
            last_name='Polo',
            email='test@example.com',
            password='testpass123'
        )

        # Create Apps for each Authentication Flow
        self.authorization_code_app = baker.make(
            Application,
            name='Test Code App',
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris='http://localhost:8000/callback',
            user=self.user,
            client_id='code-client-id',
            client_secret='code-client-secret',
        )

        self.implicit_app = baker.make(
            Application,
            name='Test Implicit App',
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            redirect_uris='http://localhost:8000/callback',
            user=self.user,
            client_id='implicit-client-id',
            client_secret='implicit-client-secret'
        )

        self.client_credentials_app = baker.make(
            Application,
            name='Test Credentials App',
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            user=self.user,
            client_id='credentials-client-id',
            client_secret='credentials-client-secret'
        )

        self.resource_password_app = baker.make(
            Application,
            name='Test Password App',
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            user=self.user,
            client_id='password-client-id',
            client_secret='password-client-secret'
        )

    def create_authorization_header(self, client_id, client_secret):
        credentials = base64.b64encode(
            f"{client_id}:{client_secret}".encode()
        ).decode('utf-8')
        return {'HTTP_AUTHORIZATION': f'Basic {credentials}'}

    def test_authorization_code_flow(self):
        """Test the complete Authorization Code flow"""

        # Step 1: Authorize Application
        auth_params = {
            'response_type': 'code',
            'client_id': self.authorization_code_app.client_id,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_challenge': 'XRi41b-5yHtTojvCpXFpsLUnmGFz6xR15c3vpPANAvM',
            'code_challenge_method': 'S256'
        }

        # Get the authorization code
        breakpoint()
        response = self.client.get(reverse('oauth2_provider:authorize'), auth_params)
        self.assertEqual(response.status_code, 302)

        # Login the user
        self.client.login(username='testuser', password='testpass123')

        # Submit the authorization form
        response = self.client.post(
            reverse('oauth2_provider:authorize'),
            {
                'client_id': self.authorization_code_app.client_id,
                'client_secret': self.authorization_code_app.client_secret,
                'state': auth_params['state'],
                'redirect_uri': auth_params['redirect_uri'],
                'response_type': 'code',
                'allow': 'Authorize',
                'scope': auth_params['scope']
            }
        )

        self.assertEqual(response.status_code, 302)

        # Extract authorization code from redirect URL
        query_params = parse_qs(urlparse(response['Location']).query)
        self.assertIn('code', query_params)
        auth_code = query_params['code'][0]

        # Step 2: Token Request
        token_url = reverse('oauth2_provider:token')
        token_data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': 'http://localhost:8000/callback',
        }

        response = self.client.post(
            token_url,
            token_data,
            **self.create_authorization_header(
                self.authorization_code_app.client_id,
                self.authorization_code_app.client_secret
            )
        )

        self.assertEqual(response.status_code, 200)
        token_response = json.loads(response.content)

        # Verify response contains required OAuth2 and OIDC fields
        self.assertIn('access_token', token_response)
        self.assertIn('refresh_token', token_response)
        self.assertIn('id_token', token_response)
        self.assertIn('token_type', token_response)
        self.assertIn('expires_in', token_response)

        # Verify ID Token
        id_token = token_response['id_token']
        decoded_token = jwt.decode(
            id_token,
            settings.OIDC_RSA_PRIVATE_KEY,
            algorithms=['RS256']
        )

        self.assertEqual(decoded_token['sub'], str(self.user.id))
        self.assertEqual(decoded_token['email'], self.user.email)
        self.assertEqual(decoded_token['nonce'], auth_params['nonce'])

    def test_implicit_flow(self):
        """Test the Implicit flow"""

        # Login the user
        self.client.login(username='testuser', password='testpass123')

        auth_params = {
            'response_type': 'token id_token',
            'client_id': self.implicit_app.client_id,
            'redirect_uri': 'http://localhost:8000/callback',
            'scope': 'openid profile email',
            'state': 'random_state_string',
            'nonce': 'random_nonce_string'
        }

        response = self.client.post(
            reverse('oauth2_provider:authorize'),
            {
                **auth_params,
                'allow': 'Authorize'
            }
        )

        self.assertEqual(response.status_code, 302)
        fragment = urlparse(response['Location']).fragment
        response_params = parse_qs(fragment)

        # Verify response contains required parameters
        self.assertIn('access_token', response_params)
        self.assertIn('id_token', response_params)
        self.assertIn('state', response_params)
        self.assertEqual(response_params['state'][0], auth_params['state'])

    def test_client_credentials_flow(self):
        """Test the Client Credentials flow"""

        token_url = reverse('oauth2_provider:token')
        response = self.client.post(
            token_url,
            {
                'grant_type': 'client_credentials',
                'scope': 'read write'
            },
            **self.create_authorization_header(
                self.client_credentials_app.client_id,
                self.client_credentials_app.client_secret
            )
        )

        self.assertEqual(response.status_code, 200)
        token_response = json.loads(response.content)

        self.assertIn('access_token', token_response)
        self.assertIn('expires_in', token_response)
        self.assertEqual(token_response['token_type'], 'Bearer')

    def test_password_flow(self):
        """Test the Resource Owner Password Credentials flow"""

        token_url = reverse('oauth2_provider:token')
        response = self.client.post(
            token_url,
            {
                'grant_type': 'password',
                'username': 'testuser',
                'password': 'testpass123',
                'scope': 'read write'
            },
            **self.create_authorization_header(
                self.resource_password_app.client_id,
                self.resource_password_app.client_secret
            )
        )

        self.assertEqual(response.status_code, 200)
        token_response = json.loads(response.content)

        self.assertIn('access_token', token_response)
        self.assertIn('refresh_token', token_response)
        self.assertIn('expires_in', token_response)
        self.assertEqual(token_response['token_type'], 'Bearer')

    def test_refresh_token_flow(self):
        """Test the Refresh Token flow"""

        # First, get a refresh token through password flow
        token_url = reverse('oauth2_provider:token')
        response = self.client.post(
            token_url,
            {
                'grant_type': 'password',
                'username': 'testuser',
                'password': 'testpass123',
                'scope': 'read write'
            },
            **self.create_authorization_header(
                self.resource_password_app.client_id,
                self.resource_password_app.client_secret
            )
        )

        first_token_response = json.loads(response.content)
        refresh_token = first_token_response['refresh_token']

        # Now use the refresh token to get a new access token
        response = self.client.post(
            token_url,
            {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'scope': 'read write'
            },
            **self.create_authorization_header(
                self.resource_password_app.client_id,
                self.resource_password_app.client_secret
            )
        )

        self.assertEqual(response.status_code, 200)
        token_response = json.loads(response.content)

        self.assertIn('access_token', token_response)
        self.assertIn('refresh_token', token_response)
        self.assertNotEqual(
            token_response['refresh_token'],
            refresh_token,
            "New refresh token should be different"
        )

    def test_userinfo_endpoint(self):
        """Test the UserInfo endpoint"""

        # First get an access token
        token_url = reverse('oauth2_provider:token')
        response = self.client.post(
            token_url,
            {
                'grant_type': 'password',
                'username': 'testuser',
                'password': 'testpass123',
                'scope': 'openid profile email'
            },
            **self.create_authorization_header(
                self.resource_password_app.client_id,
                self.resource_password_app.client_secret
            )
        )

        token_response = json.loads(response.content)
        access_token = token_response['access_token']

        # Test UserInfo endpoint
        userinfo_url = reverse('oauth2_provider:user-info')
        response = self.client.get(
            userinfo_url,
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )

        self.assertEqual(response.status_code, 200)
        userinfo = json.loads(response.content)

        self.assertEqual(userinfo['sub'], str(self.user.id))
        self.assertEqual(userinfo['email'], self.user.email)
        self.assertEqual(userinfo['preferred_username'], self.user.username)

    def test_token_revocation(self):
        """Test token revocation"""

        # First get an access token
        token_url = reverse('oauth2_provider:token')
        response = self.client.post(
            token_url,
            {
                'grant_type': 'password',
                'username': 'testuser',
                'password': 'testpass123',
                'scope': 'read write'
            },
            **self.create_authorization_header(
                self.resource_password_app.client_id,
                self.resource_password_app.client_secret
            )
        )

        token_response = json.loads(response.content)
        access_token = token_response['access_token']

        # Revoke the token
        revoke_url = reverse('oauth2_provider:revoke-token')
        response = self.client.post(
            revoke_url,
            {
                'token': access_token,
                'client_id': self.resource_password_app.client_id,
                'client_secret': self.resource_password_app.client_secret
            }
        )

        self.assertEqual(response.status_code, 200)

        # Try to use the revoked token
        userinfo_url = reverse('oauth2_provider:user-info')
        response = self.client.get(
            userinfo_url,
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )

        self.assertEqual(response.status_code, 401)

    def test_token_introspection(self):
        """Test token introspection endpoint"""

        # First get an access token
        token_url = reverse('oauth2_provider:token')
        response = self.client.post(
            token_url,
            {
                'grant_type': 'password',
                'username': 'testuser',
                'password': 'testpass123',
                'scope': 'read write'
            },
            **self.create_authorization_header(
                self.resource_password_app.client_id,
                self.resource_password_app.client_secret
            )
        )

        token_response = json.loads(response.content)
        access_token = token_response['access_token']

        # Test introspection
        introspect_url = reverse('oauth2_provider:introspect')
        response = self.client.post(
            introspect_url,
            {
                'token': access_token,
                'client_id': self.resource_password_app.client_id,
                'client_secret': self.resource_password_app.client_secret
            }
        )

        self.assertEqual(response.status_code, 200)
        introspection = json.loads(response.content)

        self.assertTrue(introspection['active'])
        self.assertEqual(introspection['username'], 'testuser')
        self.assertEqual(introspection['client_id'], self.resource_password_app.client_id)
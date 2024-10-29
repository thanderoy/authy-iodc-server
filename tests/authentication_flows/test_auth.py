import base64
import hashlib
import json
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import cryptography
import jwt
import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from model_bakery import baker
from oauth2_provider.models import AccessToken, Application, RefreshToken

User = get_user_model()


class OAuth2AuthFlows(TestCase):
    def setUp(self):
        self.client = Client()

        self.user = User.objects.create_user(
            first_name='Marco',
            last_name='Polo',
            email='test@example.com',
            password='testpass123',
            is_active=True
        )

        # Create Apps for each Authentication Flow
        self.authorization_code_app = baker.make(
            Application,
            name='Test Code App',
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris='http://localhost:8000/callback',
            user=self.user, algorithm='RS256',
            client_id=settings.TEST_CLIENT_ID,
            client_secret=settings.TEST_CLIENT_SECRET,
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

        code_verifier = 'KP6RC7E3K9U2OD8ZETN3WT0URYAR9BIPS8AZQPKU41HBOQJRYM'
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        # Step 1: Authorize Application
        auth_params = {
            'response_type': 'code',
            'client_id': self.authorization_code_app.client_id,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'scope': 'openid',
        }

        # Login first
        login_status = self.client.login(
            username='test@example.com', password='testpass123')
        self.assertTrue(login_status, True)

        # Get the authorization code
        response = self.client.get(
            reverse('oauth2_provider:authorize'),
            auth_params
        )

        # Handle consent form
        self.assertEqual(response.status_code, 200)
        consent_response = self.client.post(
            reverse('oauth2_provider:authorize'),
            {
                'client_id': self.authorization_code_app.client_id,
                'redirect_uri': auth_params['redirect_uri'],
                'response_type': 'code',
                'allow': 'Authorize',  # This simulates clicking "Allow"
                'scope': auth_params['scope'],
                'code_challenge': auth_params['code_challenge'],
                'code_challenge_method': auth_params['code_challenge_method']
            }
        )
        self.assertEqual(consent_response.status_code, 302)

        # Extract authorization code from redirect URL
        _auth_code = parse_qs(urlparse(consent_response['Location']).query)
        self.assertIn('code', _auth_code)
        auth_code = _auth_code['code'][0]

        # Step 2: Token Request
        token_payload = {
            "client_id": settings.TEST_CLIENT_ID,
            "client_secret": settings.TEST_CLIENT_SECRET,
            "code": auth_code,
            "code_verifier": code_verifier,
            "redirect_uri": auth_params['redirect_uri'],
            "grant_type": 'authorization_code',
        }
        encoded_data = "&".join(
            f"{key}={value}" for key, value in token_payload.items())

        _token_response = self.client.post(
            reverse('oauth2_provider:token'),
            data=encoded_data,
            content_type='application/x-www-form-urlencoded',
            HTTP_CACHE_CONTROL='no-cache'
        )

        self.assertEqual(_token_response.status_code, 200)
        token_response = json.loads(_token_response.content)

        self.assertIn('access_token', token_response)
        self.assertIn('refresh_token', token_response)
        self.assertIn('id_token', token_response)
        self.assertIn('token_type', token_response)
        self.assertIn('expires_in', token_response)

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
        self.assertEqual(
            introspection['client_id'], self.resource_password_app.client_id)

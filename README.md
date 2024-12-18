# authy-iodc-server


# OAuth2 and OIDC Authorization Server

A robust OAuth2 and OpenID Connect (OIDC) authorization server implementation supporting multiple authentication flows. This server provides secure authentication and authorization capabilities for various client application types.

## Supported Authentication Flows

### 1. Authorization Code Flow

The most secure and recommended flow for applications that can securely store client secrets. Ideal for web applications with backend servers.

#### Implementation Example
```python
auth_params = {
    'response_type': 'code',
    'client_id': '[YOUR_CLIENT_ID]',
    'redirect_uri': 'http://localhost:8000/callback',
    'code_challenge': '[CODE_CHALLENGE]',
    'code_challenge_method': 'S256',
    'scope': 'openid',
}
```

#### Flow Steps:
1. Client initiates authentication request with the above parameters
2. User authenticates and grants consent
3. Authorization server returns authorization code
4. Client exchanges code for tokens using back-channel request
5. Tokens returned include access_token, refresh_token, and id_token

### 2. Client Credentials Flow

Server-to-server authentication where no user interaction is required. Perfect for microservices architecture and automated processes.

#### Implementation Example
```python
auth_headers = base64.b64encode(
    f"{client_id}:{client_secret}".encode('utf-8')
).decode('utf-8')

data = {'grant_type': 'client_credentials'}

# Token request
response = requests.post(
    'token_endpoint',
    data=data,
    headers={'Authorization': f'Basic {auth_headers}'}
)
```

#### Key Features:
- No user interaction required
- Simplified token acquisition process
- Client authentication using client_id and client_secret
- Returns access_token only (no refresh token)

### 3. Resource Owner Password Credentials Flow

**Note**: This flow should only be used for legacy applications that cannot be updated to use more secure flows.

#### Implementation Example
```python
data = {
    'grant_type': 'password',
    'username': '[USER_EMAIL]',
    'password': '[USER_PASSWORD]',
    'scope': 'openid read'
}
```

#### Security Considerations:
- Only use for legacy system migration
- Does not support MFA
- Requires direct handling of user credentials

### 4. Refresh Token Flow

The Refresh Token flow enables clients to obtain new access tokens without requiring user re-authentication.

#### Implementation Example
```python
refresh_token_payload = {
    'grant_type': 'refresh_token',
    'refresh_token': '[REFRESH_TOKEN]',
    'scope': 'openid read'
}

response = requests.post(
    'token_endpoint',
    data=refresh_token_payload,
    headers={'Authorization': f'Basic {auth_headers}'}
)
```

#### Key Characteristics:
- Enables long-term API access without user re-authentication
- Typically has longer lifetime than access tokens
- Available in Authorization Code and Password Credentials flows
- Not available in Client Credentials or Implicit flows

#### Refresh Token Support by Flow Type:
| Flow Type | Includes Refresh Token |
|-----------|----------------------|
| Authorization Code | Yes |
| Implicit | No |
| Client Credentials | No |
| Password Credentials | Yes |
| Hybrid | Yes |
| Device | Yes |

#### Security Best Practices for Refresh Tokens:
1. Store refresh tokens securely
2. Implement token rotation (new refresh token with each use)
3. Set appropriate expiration times based on security requirements
4. Implement refresh token revocation on logout
5. Use refresh tokens only over secure channels (HTTPS)

## Additional Features

### Token Introspection
Verify token validity and get token information:

```python
response = requests.post(
    'introspection_endpoint',
    data={
        'token': access_token,
        'client_id': client_id,
        'client_secret': client_secret,
    }
)
```

### UserInfo Endpoint
Retrieve authenticated user information:

```python
response = requests.get(
    'userinfo_endpoint',
    headers={'Authorization': f'Bearer {access_token}'}
)
```

### Token Revocation
Invalidate active tokens:

```python
response = requests.post(
    'revocation_endpoint',
    data={
        'token': access_token,
        'client_id': client_id,
        'client_secret': client_secret,
    }
)
```

## Security Best Practices

1. Always use HTTPS for all endpoints
2. Implement PKCE with Authorization Code flow
3. Store client secrets securely
4. Use appropriate token expiration times
5. Validate all redirect URIs
6. Implement rate limiting on token endpoints
7. Rotate refresh tokens on use
8. Implement proper token storage mechanisms
9. Use token revocation when sessions end

## Getting Started

1. Register your application to get client credentials
2. Choose the appropriate flow based on your use case
3. Implement the required endpoints in your client application
4. Test the flow using the provided example code

## API Endpoints

- Authorization: `/oauth2/authorize`
- Token: `/oauth2/token`
- UserInfo: `/oauth2/userinfo`
- Introspection: `/oauth2/introspect`
- Revocation: `/oauth2/revoke`

## Example Applications

Check the `tests` directory for complete implementation examples of each flow, including:
- Web application using Authorization Code flow
- Service application using Client Credentials flow
- Legacy application using Password flow
- Token management and introspection examples
- Refresh token implementation examples

## License

This project is licensed under the MIT License - see the LICENSE.md file for details
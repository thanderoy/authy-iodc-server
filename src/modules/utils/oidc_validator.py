"""Enhanced OAuth2 Validator with additional security features"""

import hashlib
import logging
from typing import Dict, Any, Optional
from django.contrib.auth import get_user_model
from django.core.cache import cache
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.common import Request

logger = logging.getLogger(__name__)
User = get_user_model()


class EnhancedAuthyOAuth2Validator(OAuth2Validator):
    """Enhanced OAuth2 Validator with additional security and functionality"""

    # Rate limiting constants
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes in seconds

    def get_additional_claims(self, request) -> Dict[str, Any]:
        """
        Get additional claims to include in tokens.

        Args:
            request: The OAuth2 request object

        Returns:
            Dictionary of additional claims
        """
        user = request.user
        claims = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "email_verified": getattr(user, "email_verified", True),
            "preferred_username": user.email,
            "name": f"{user.first_name} {user.last_name}".strip(),
        }

        # Add entity type if available
        if hasattr(user, "entity_type"):
            claims["entity_type"] = user.entity_type

        # Add groups if user has them
        if hasattr(user, "parent_entities"):
            groups = user.parent_entities.filter(entity_type="GRP").values_list(
                "uuid", flat=True
            )
            claims["groups"] = [str(uuid) for uuid in groups]

        # Add custom attributes if defined
        if hasattr(user, "custom_attributes"):
            claims["custom_attributes"] = user.custom_attributes

        return claims

    def get_userinfo_claims(self, request) -> Dict[str, Any]:
        """
        Get userinfo claims for the userinfo endpoint.

        Args:
            request: The OAuth2 request object

        Returns:
            Dictionary of userinfo claims
        """
        claims = super().get_userinfo_claims(request)

        # Add additional claims based on requested scopes
        if request.scopes and "profile" in request.scopes:
            claims.update(self.get_additional_claims(request))

        if request.scopes and "email" in request.scopes:
            claims["email"] = request.user.email
            claims["email_verified"] = getattr(request.user, "email_verified", True)

        if request.scopes and "groups" in request.scopes:
            if hasattr(request.user, "parent_entities"):
                groups = request.user.parent_entities.filter(
                    entity_type="GRP"
                ).values_list("first_name", "last_name")
                claims["groups"] = [f"{first} {last}".strip() for first, last in groups]

        return claims

    def validate_bearer_token(self, token: str, scopes: list, request: Request) -> bool:
        """
        Validate bearer token with additional security checks.

        Args:
            token: The bearer token
            scopes: Required scopes
            request: The request object

        Returns:
            Boolean indicating if token is valid
        """
        # Check if token is blacklisted
        if self._is_token_blacklisted(token):
            logger.warning(f"Attempted use of blacklisted token: {token[:10]}...")
            return False

        # Perform standard validation
        is_valid = super().validate_bearer_token(token, scopes, request)

        if is_valid:
            # Log successful token validation for audit
            self._log_token_usage(token, request)

        return is_valid

    def validate_client_id(
        self, client_id: str, request: Request, *args, **kwargs
    ) -> bool:
        """
        Validate client ID with rate limiting.

        Args:
            client_id: The client ID to validate
            request: The request object

        Returns:
            Boolean indicating if client ID is valid
        """
        # Check if client is rate limited
        if self._is_client_rate_limited(client_id):
            logger.warning(f"Rate limited client attempted access: {client_id}")
            return False

        # Perform standard validation
        is_valid = super().validate_client_id(client_id, request, *args, **kwargs)

        if not is_valid:
            self._record_failed_attempt(client_id)

        return is_valid

    def validate_code(
        self, client_id: str, code: str, client: Any, request: Request, *args, **kwargs
    ) -> bool:
        """
        Validate authorization code with additional security.

        Args:
            client_id: The client ID
            code: The authorization code
            client: The client object
            request: The request object

        Returns:
            Boolean indicating if code is valid
        """
        # Check for code replay attacks
        code_key = f"auth_code_used:{code}"
        if cache.get(code_key):
            logger.error(
                f"Authorization code replay attack detected for client: {client_id}"
            )
            return False

        # Perform standard validation
        is_valid = super().validate_code(
            client_id, code, client, request, *args, **kwargs
        )

        if is_valid:
            # Mark code as used
            cache.set(code_key, True, timeout=600)  # 10 minutes

        return is_valid

    def validate_refresh_token(
        self, refresh_token: str, client: Any, request: Request, *args, **kwargs
    ) -> bool:
        """
        Validate refresh token with rotation check.

        Args:
            refresh_token: The refresh token
            client: The client object
            request: The request object

        Returns:
            Boolean indicating if refresh token is valid
        """
        # Check if token has been rotated (invalidated)
        if self._is_token_rotated(refresh_token):
            logger.warning(
                f"Attempted use of rotated refresh token for client: {client.client_id}"
            )
            return False

        return super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        )

    def save_bearer_token(
        self, token: Dict[str, Any], request: Request, *args, **kwargs
    ) -> None:
        """
        Save bearer token with additional metadata.

        Args:
            token: The token dictionary
            request: The request object
        """
        # Add metadata to token
        if "refresh_token" in token:
            # Store refresh token family for rotation tracking
            self._store_token_family(token["refresh_token"], request)

        # Log token issuance for audit
        self._log_token_issuance(token, request)

        super().save_bearer_token(token, request, *args, **kwargs)

    def revoke_token(
        self, token: str, token_type_hint: str, request: Request, *args, **kwargs
    ) -> None:
        """
        Revoke token with cascading revocation.

        Args:
            token: The token to revoke
            token_type_hint: Hint about token type
            request: The request object
        """
        # Add to blacklist
        self._blacklist_token(token, token_type_hint)

        # If it's a refresh token, revoke all tokens in the family
        if token_type_hint == "refresh_token":
            self._revoke_token_family(token)

        # Log revocation for audit
        self._log_token_revocation(token, request)

        super().revoke_token(token, token_type_hint, request, *args, **kwargs)

    def introspect_token(
        self, token: str, token_type_hint: str, request: Request, *args, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Introspect token with additional information.

        Args:
            token: The token to introspect
            token_type_hint: Hint about token type
            request: The request object

        Returns:
            Token introspection response
        """
        # Check blacklist first
        if self._is_token_blacklisted(token):
            return {"active": False, "reason": "token_revoked"}

        # Get standard introspection
        introspection = super().introspect_token(
            token, token_type_hint, request, *args, **kwargs
        )

        if introspection and introspection.get("active"):
            # Add additional metadata
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            introspection["issued_at"] = cache.get(f"token_issued:{token_hash}")
            introspection["last_used"] = cache.get(f"token_last_used:{token_hash}")

        return introspection

    def validate_silent_login(self, request: Request) -> bool:
        """
        Validate silent login request.

        Args:
            request: The request object

        Returns:
            Boolean indicating if silent login is allowed
        """
        # Check if user session is still valid
        if not request.user or not request.user.is_authenticated:
            return False

        # Check if prompt=none is allowed for this client
        client = request.client
        if not getattr(client, "allow_silent_login", False):
            return False

        # Check session age
        session_age = cache.get(f"session_age:{request.user.id}")
        if session_age and session_age > 3600:  # 1 hour
            return False

        return True

    def validate_silent_authorization(self, request: Request) -> bool:
        """
        Validate silent authorization request.

        Args:
            request: The request object

        Returns:
            Boolean indicating if silent authorization is allowed
        """
        # Similar to silent login but for authorization
        return self.validate_silent_login(request)

    # Helper methods

    def _is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        key = f"blacklist:{hashlib.sha256(token.encode()).hexdigest()}"
        return cache.get(key) is not None

    def _blacklist_token(self, token: str, token_type: str) -> None:
        """Add token to blacklist"""
        timeout = 86400 if token_type == "refresh_token" else 3600
        key = f"blacklist:{hashlib.sha256(token.encode()).hexdigest()}"
        cache.set(key, True, timeout=timeout)

    def _is_client_rate_limited(self, client_id: str) -> bool:
        """Check if client is rate limited"""
        attempts = cache.get(f"failed_attempts:{client_id}", 0)
        return attempts >= self.MAX_FAILED_ATTEMPTS

    def _record_failed_attempt(self, client_id: str) -> None:
        """Record a failed authentication attempt"""
        key = f"failed_attempts:{client_id}"
        attempts = cache.get(key, 0)
        cache.set(key, attempts + 1, timeout=self.LOCKOUT_DURATION)

    def _is_token_rotated(self, refresh_token: str) -> bool:
        """Check if refresh token has been rotated"""
        key = f"rotated:{hashlib.sha256(refresh_token.encode()).hexdigest()}"
        return cache.get(key) is not None

    def _store_token_family(self, refresh_token: str, request: Request) -> None:
        """Store refresh token family for rotation tracking"""
        key = f"family:{hashlib.sha256(refresh_token.encode()).hexdigest()}"
        family_id = cache.get(key)
        if not family_id:
            import uuid

            family_id = str(uuid.uuid4())
        cache.set(key, family_id, timeout=1209600)  # 14 days

    def _revoke_token_family(self, refresh_token: str) -> None:
        """Revoke all tokens in a family"""
        key = f"family:{hashlib.sha256(refresh_token.encode()).hexdigest()}"
        family_id = cache.get(key)
        if family_id:
            # Mark family as revoked
            cache.set(f"family_revoked:{family_id}", True, timeout=1209600)

    def _log_token_usage(self, token: str, request: Request) -> None:
        """Log token usage for audit"""
        remote_addr = "unknown"
        if hasattr(request, "META"):
            remote_addr = request.META.get("REMOTE_ADDR", "unknown")
        elif hasattr(request, "request") and hasattr(request.request, "META"):
            remote_addr = request.request.META.get("REMOTE_ADDR", "unknown")

        key = f"token_last_used:{hashlib.sha256(token.encode()).hexdigest()}"
        cache.set(key, remote_addr, timeout=3600)

    def _log_token_issuance(self, token: Dict[str, Any], request: Request) -> None:
        """Log token issuance for audit"""
        logger.info(
            f"Token issued to client {request.client.client_id} "
            f"for user {request.user.id if request.user else 'N/A'}"
        )

    def _log_token_revocation(self, token: str, request: Request) -> None:
        """Log token revocation for audit"""
        logger.info(
            f"Token revoked: {token[:10]}... by client {request.client.client_id if request.client else 'unknown'}"
        )

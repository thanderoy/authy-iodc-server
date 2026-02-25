"""Security middleware for Authy OIDC Server"""

import logging
import time
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger(__name__)


class RateLimitMiddleware(MiddlewareMixin):
    """Rate limiting middleware for API endpoints"""

    DEFAULT_RATE_LIMIT = 100  # requests per minute
    TOKEN_ENDPOINT_LIMIT = 10  # requests per minute for token endpoints

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Process incoming request and check rate limits"""

        # Skip rate limiting for internal IPs in debug mode
        if settings.DEBUG and request.META.get("REMOTE_ADDR") in [
            "127.0.0.1",
            "localhost",
        ]:
            return None

        # Get client identifier (IP address or authenticated user)
        client_id = self._get_client_identifier(request)

        # Get rate limit for the endpoint
        rate_limit = self._get_rate_limit_for_endpoint(request.path)

        # Check rate limit
        cache_key = f"rate_limit:{client_id}:{request.path}"
        request_count = cache.get(cache_key, 0)

        if request_count >= rate_limit:
            logger.warning(f"Rate limit exceeded for {client_id} on {request.path}")
            return JsonResponse(
                {
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                },
                status=429,
            )

        # Increment counter
        cache.set(cache_key, request_count + 1, timeout=60)

        return None

    def _get_client_identifier(self, request: HttpRequest) -> str:
        """Get unique identifier for the client"""
        if request.user and request.user.is_authenticated:
            return f"user:{request.user.id}"
        return f"ip:{request.META.get('REMOTE_ADDR', 'unknown')}"

    def _get_rate_limit_for_endpoint(self, path: str) -> int:
        """Get rate limit for specific endpoint"""
        if "/token" in path or "/authorize" in path:
            return self.TOKEN_ENDPOINT_LIMIT
        return self.DEFAULT_RATE_LIMIT


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Add security headers to responses"""

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Add security headers to the response"""

        # Content Security Policy
        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Additional security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        )

        # Strict Transport Security (only for HTTPS)
        if request.is_secure():
            response["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


class AuditLoggingMiddleware(MiddlewareMixin):
    """Audit logging for sensitive operations"""

    SENSITIVE_ENDPOINTS = [
        "/o/token/",
        "/o/authorize/",
        "/o/revoke/",
        "/o/introspect/",
        "/admin/",
        "/entities/",
    ]

    def process_request(self, request: HttpRequest) -> None:
        """Log incoming requests to sensitive endpoints"""
        request._start_time = time.time()  # type: ignore

        if any(endpoint in request.path for endpoint in self.SENSITIVE_ENDPOINTS):
            logger.info(
                f"Audit: {request.method} {request.path} from "
                f"{request.META.get('REMOTE_ADDR', 'unknown')} "
                f"User: {request.user.id if request.user.is_authenticated else 'Anonymous'}"
            )

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Log response for sensitive endpoints"""

        if hasattr(request, "_start_time"):
            duration = time.time() - request._start_time

            if any(endpoint in request.path for endpoint in self.SENSITIVE_ENDPOINTS):
                logger.info(
                    f"Audit Response: {request.method} {request.path} "
                    f"Status: {response.status_code} "
                    f"Duration: {duration:.3f}s"
                )

        return response

    def process_exception(self, request: HttpRequest, exception: Exception) -> None:
        """Log exceptions in sensitive endpoints"""

        if any(endpoint in request.path for endpoint in self.SENSITIVE_ENDPOINTS):
            logger.error(
                f"Audit Exception: {request.method} {request.path} "
                f"Exception: {type(exception).__name__}: {str(exception)} "
                f"User: {request.user.id if request.user.is_authenticated else 'Anonymous'}"
            )


class IPWhitelistMiddleware(MiddlewareMixin):
    """IP whitelist middleware for admin and sensitive endpoints"""

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Check if IP is whitelisted for sensitive endpoints"""

        # Only apply to admin endpoints
        if not request.path.startswith("/admin/"):
            return None

        # Skip in debug mode
        if settings.DEBUG:
            return None

        # Get whitelisted IPs from settings
        whitelisted_ips = getattr(settings, "ADMIN_IP_WHITELIST", [])

        if not whitelisted_ips:
            # If no whitelist is configured, allow all (but log warning)
            logger.warning("No IP whitelist configured for admin access")
            return None

        client_ip = request.META.get("REMOTE_ADDR", "")

        # Check if client IP is in whitelist
        if client_ip not in whitelisted_ips:
            logger.warning(f"Unauthorized admin access attempt from {client_ip}")
            return JsonResponse(
                {"error": "forbidden", "message": "Access denied"}, status=403
            )

        return None


class RequestSizeMiddleware(MiddlewareMixin):
    """Limit request body size to prevent DoS attacks"""

    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Check request body size"""

        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.META.get("CONTENT_LENGTH")

            if content_length:
                try:
                    size = int(content_length)
                    if size > self.MAX_REQUEST_SIZE:
                        logger.warning(
                            f"Request too large: {size} bytes from "
                            f"{request.META.get('REMOTE_ADDR', 'unknown')}"
                        )
                        return JsonResponse(
                            {
                                "error": "request_too_large",
                                "message": "Request body too large",
                            },
                            status=413,
                        )
                except (ValueError, TypeError):
                    pass

        return None


class SessionSecurityMiddleware(MiddlewareMixin):
    """Enhanced session security"""

    def process_request(self, request: HttpRequest) -> None:
        """Process request and check session security"""

        if request.user.is_authenticated:
            # Check for session hijacking by comparing IP
            session_ip = request.session.get("ip_address")
            current_ip = request.META.get("REMOTE_ADDR")

            if session_ip and session_ip != current_ip:
                logger.warning(
                    f"Possible session hijacking detected. "
                    f"User: {request.user.id}, "
                    f"Session IP: {session_ip}, Current IP: {current_ip}"
                )
                # Optionally invalidate the session
                # request.session.flush()

            # Store/update session IP
            if not session_ip:
                request.session["ip_address"] = current_ip

            # Update last activity timestamp
            request.session["last_activity"] = time.time()

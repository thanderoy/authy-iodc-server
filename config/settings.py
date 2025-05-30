"""Authy OIDC Settings"""
from pathlib import Path
import os

import dj_database_url


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'a-default-fallback-key-that-will-be-overridden-in-tests')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'oauth2_provider',
    'corsheaders',
    'rest_framework',
    'drf_spectacular',
]

LOCAL_APPS = [
    'modules.entities',
]

INSTALLED_APPS += LOCAL_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',    # Above CommonMiddleware & WhiteNoiseMiddleware - *from docs. # noqa: E501
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'oauth2_provider.middleware.OAuth2TokenMiddleware',     # Access Tokens
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ORIGIN_ALLOW_ALL = True

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": dj_database_url.parse(f"sqlite:///{BASE_DIR}/db.sqlite3"),
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',     # noqa: E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',   # noqa: E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',  # noqa: E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',     # noqa: E501
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Docs
SPECTACULAR_SETTINGS = {
    'TITLE': 'Authy OIDC Server',
    'DESCRIPTION': 'Authy OIDC Server - OAuth2 + OIDC Identity Provider.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'EXAMPLES_INCLUDE_RESPONSE': True,
}

# AUTH RELATED
AUTH_USER_MODEL = 'entities.Entity'
LOGIN_URL = '/admin/login/'

AUTHENTICATION_BACKENDS = [
    'oauth2_provider.backends.OAuth2Backend',
    # Uncomment following if you want to access the admin
    'django.contrib.auth.backends.ModelBackend',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10
}

# Define a default valid RSA key for use when the env var isn't set
_DEFAULT_OIDC_RSA_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
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

OIDC_RSA_PRIVATE_KEY = os.environ.get('OIDC_RSA_PRIVATE_KEY', _DEFAULT_OIDC_RSA_PRIVATE_KEY_PEM)

OAUTH2_PROVIDER = {
    'SCOPES': {
        'openid': 'OpenID Connect scope',
        'read': 'Read scope',
        'write': 'Write scope',
        'groups': 'Access to groups'
    },
    'OIDC_ENABLED': True,
    'OIDC_RSA_PRIVATE_KEY': OIDC_RSA_PRIVATE_KEY, # This will now always have a value
    'OIDC_ISS_ENDPOINT': os.environ.get("OIDC_ISS_ENDPOINT", "http://localhost:8000/o"), # noqa
    'OIDC_USERINFO_ENDPOINT': os.environ.get("OIDC_USERINFO_ENDPOINT", "http://localhost:8000/o/userinfo"), # noqa
    'PKCE_REQUIRED': True, # Often True by default in modern OIDC
    'ALLOWED_REDIRECT_URI_SCHEMES': ['http', 'https', 'myapp'], # Example
    'ACCESS_TOKEN_EXPIRE_SECONDS': int(os.environ.get('ACCESS_TOKEN_EXPIRE_SECONDS', 36000)), # noqa
    'REFRESH_TOKEN_EXPIRE_SECONDS': int(os.environ.get('REFRESH_TOKEN_EXPIRE_SECONDS', 864000)), # noqa
    "ERROR_RESPONSE_WITH_SCOPES": True, # Useful for debugging
    # Ensure OAUTH2_VALIDATOR_CLASS is present if it was there before
    "OAUTH2_VALIDATOR_CLASS": "modules.utils.oidc_validator.AuthyOAuth2Validator",
    "REQUEST_APPROVAL_PROMPT": "auto", # Was in original, keeping it
}

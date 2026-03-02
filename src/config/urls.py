"""Authy OIDC URLs"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from oauth2_provider import urls as oauth2_urls

from modules.entities.mixins import BrandedAuthMixin
from modules.entities.views import RegisterView


# -- Branded auth views (inject app branding via client_id) ----------------


class BrandedLoginView(BrandedAuthMixin, auth_views.LoginView):
    redirect_authenticated_user = True


class BrandedLogoutView(BrandedAuthMixin, auth_views.LogoutView):
    next_page = "/"


class BrandedPasswordResetView(BrandedAuthMixin, auth_views.PasswordResetView):
    pass


class BrandedPasswordResetDoneView(BrandedAuthMixin, auth_views.PasswordResetDoneView):
    pass


class BrandedPasswordResetConfirmView(
    BrandedAuthMixin, auth_views.PasswordResetConfirmView
):
    pass


class BrandedPasswordResetCompleteView(
    BrandedAuthMixin, auth_views.PasswordResetCompleteView
):
    pass


class BrandedRegisterView(BrandedAuthMixin, RegisterView):
    pass


# --------------------------------------------------------------------------

urlpatterns = [
    path("admin/", admin.site.urls),
    path("o/", include(oauth2_urls)),
    path("entities/", include("modules.entities.urls", namespace="entities")),
    path("register/", BrandedRegisterView.as_view(), name="register"),
    path("login/", BrandedLoginView.as_view(), name="login"),
    path("logout/", BrandedLogoutView.as_view(), name="logout"),
    path(
        "password_reset/",
        BrandedPasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "password_reset/done/",
        BrandedPasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        BrandedPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        BrandedPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]

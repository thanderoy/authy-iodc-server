"""Mixin that injects application branding into template context.

Auth views (Login, Register, Password Reset, Logout) inherit from this
mixin so the template can dynamically render a custom logo and brand
color based on the ``client_id`` query parameter passed during OIDC flows.
"""

from typing import Any

from oauth2_provider.models import get_application_model

from modules.entities.models import ApplicationBranding

Application = get_application_model()


class BrandedAuthMixin:
    """Injects ``branding`` into the template context based on ``client_id``.

    The mixin inspects ``request.GET["client_id"]`` (or falls back to
    ``request.POST["client_id"]``), looks up the matching OAuth2 Application,
    and fetches its related ``ApplicationBranding`` record. If no branding
    is found the template falls back to the default Authy look.

    The ``client_id`` is also forwarded as a hidden field so it persists
    across form submissions (e.g. login POST → redirect).
    """

    def get_branding_context(self) -> dict[str, Any]:
        client_id = self.request.GET.get(  # type: ignore[attr-defined]
            "client_id"
        ) or self.request.POST.get(  # type: ignore[attr-defined]
            "client_id", ""
        )

        context: dict[str, Any] = {"client_id": client_id}

        if not client_id:
            return context

        try:
            app = Application.objects.select_related("branding").get(
                client_id=client_id
            )
            branding: ApplicationBranding | None = getattr(app, "branding", None)
            context["app_name"] = app.name
            if branding:
                context["branding"] = branding
        except Application.DoesNotExist:
            pass

        return context

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)  # type: ignore[misc]
        context.update(self.get_branding_context())
        return context

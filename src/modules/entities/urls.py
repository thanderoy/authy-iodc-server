from django.urls import path
from rest_framework.routers import SimpleRouter

from modules.entities import views

app_name = "entities"

router = SimpleRouter()
router.register("entities", views.EntityViewSet)

urlpatterns = [
    path(
        "console/profile/", views.ConsoleProfileView.as_view(), name="console_profile"
    ),
    path(
        "console/security/",
        views.ConsoleSecurityView.as_view(),
        name="console_security",
    ),
    path(
        "console/sessions/",
        views.ConsoleSessionsView.as_view(),
        name="console_sessions",
    ),
] + router.urls

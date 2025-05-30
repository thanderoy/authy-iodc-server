from rest_framework.routers import SimpleRouter

from modules.entities import views

app_name = "entities"

from django.urls import path

router = SimpleRouter()
router.register("entities", views.EntityViewSet)


urlpatterns = [
    path("me/", views.EntityMeViewset.as_view(), name="entity-me"),
] + router.urls
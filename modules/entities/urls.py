from rest_framework.routers import SimpleRouter

from modules.entities import views

app_name = "entities"

router = SimpleRouter()
router.register("entities", views.EntityViewSet)


urlpatterns = router.urls
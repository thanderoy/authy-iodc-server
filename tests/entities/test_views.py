import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate
from modules.entities.views import EntityMeViewset, EntityViewSet

User = get_user_model()


@pytest.fixture
def api_rf():
    return APIRequestFactory()


@pytest.fixture
def auth_user():
    user = User.objects.create_user(
        first_name="Marco",
        last_name="Polo",
        email="marco@example.com",
        password="testpass123",
    )
    user.is_active = True
    user.save()
    return user


@pytest.mark.django_db
class TestEntityViews:
    def test_entity_me_retrieve(self, api_rf, auth_user):
        view = EntityMeViewset.as_view()
        request = api_rf.get("/me/")
        force_authenticate(request, user=auth_user)
        response = view(request)
        assert response.status_code == 200
        assert response.data["first_name"] == "Marco"

    def test_entity_viewset_list(self, api_rf, auth_user):
        view = EntityViewSet.as_view({"get": "list"})
        request = api_rf.get("/entities/")
        force_authenticate(request, user=auth_user)
        response = view(request)
        assert response.status_code == 200
        assert len(response.data) > 0

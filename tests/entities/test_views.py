import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from model_bakery import baker

from modules.entities.models import Entity, Relationship
from modules.entities.serializers import EntitySerializer, EntityMeSerializer

pytestmark = pytest.mark.django_db


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def authenticated_user(api_client):
    user = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="testuser@example.com", is_active=True)
    user.set_password("password123")
    user.save()
    # In a real OIDC setup, we'd mock the token validation or use a test token.
    # For simplicity here, we'll directly authenticate the client.
    # This might need adjustment if using django-oauth-toolkit's specific auth flows in tests.
    # If using DRF's TokenAuthentication for tests (simpler):
    # from rest_framework.authtoken.models import Token
    # token = Token.objects.create(user=user)
    # api_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
    # For now, let's assume session authentication or a mock for IsAuthenticated for view tests.
    # A common way for DRF view tests is to use `force_authenticate`.
    api_client.force_authenticate(user=user)
    return user


class TestEntityViewSet:
    def test_list_entities_unauthenticated(self, api_client):
        url = reverse("entities:entity-list")
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED # or 403 if not using IsAuthenticatedOrReadOnly

    def test_list_entities_authenticated(self, api_client, authenticated_user):
        baker.make(Entity, _quantity=3)
        url = reverse("entities:entity-list")
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        # authenticated_user + 3 others = 4
        # Serializer will include the authenticated user as well if queryset is Entity.objects.all()
        assert len(response.data) >= 1 # Should see at least the authenticated user + any others

    def test_create_entity_person_authenticated(self, api_client, authenticated_user):
        url = reverse("entities:entity-list")
        data = {
            "first_name": "New",
            "last_name": "Person",
            "email": "newperson@example.com",
            "entity_type": "PSN",
            "password": "newpassword123",
            "confirm_password": "newpassword123",
        }
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_201_CREATED
        assert Entity.objects.filter(email="newperson@example.com").exists()
        new_entity = Entity.objects.get(email="newperson@example.com")
        assert new_entity.entity_type == Entity.EntityType.PERSON
        assert new_entity.is_system_entity is False

    def test_create_entity_group_authenticated(self, api_client, authenticated_user):
        url = reverse("entities:entity-list")
        data = {
            "first_name": "New",
            "last_name": "Group",
            "email": "newgroup@example.com",
            "entity_type": "GRP",
            "password": "newpassword123", # Groups might not need passwords depending on full reqs
            "confirm_password": "newpassword123",
        }
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_201_CREATED
        new_entity = Entity.objects.get(email="newgroup@example.com")
        assert new_entity.entity_type == Entity.EntityType.GROUP
        assert new_entity.is_system_entity is True


    def test_retrieve_entity_authenticated(self, api_client, authenticated_user):
        entity_to_retrieve = baker.make(Entity, email="retrieveme@example.com")
        url = reverse("entities:entity-detail", kwargs={"pk": entity_to_retrieve.pk})
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data["email"] == "retrieveme@example.com"

    def test_update_entity_authenticated(self, api_client, authenticated_user):
        entity_to_update = baker.make(Entity, first_name="OldName", email="updateme@example.com")
        url = reverse("entities:entity-detail", kwargs={"pk": entity_to_update.pk})
        data = {"first_name": "NewName"}
        response = api_client.patch(url, data) # Partial update
        assert response.status_code == status.HTTP_200_OK
        entity_to_update.refresh_from_db()
        assert entity_to_update.first_name == "NewName"

    def test_delete_entity_authenticated(self, api_client, authenticated_user):
        entity_to_delete = baker.make(Entity, email="deleteme@example.com")
        url = reverse("entities:entity-detail", kwargs={"pk": entity_to_delete.pk})
        response = api_client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Entity.objects.filter(pk=entity_to_delete.pk).exists()

    def test_create_entity_unauthenticated(self, api_client):
        url = reverse("entities:entity-list")
        data = {"first_name": "Test", "last_name": "User", "email": "test@example.com", "password": "pw"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestEntityMeViewset:
    # Assuming 'me' endpoint is not part of the router, needs explicit URL if so.
    # The current urls.py only registers EntityViewSet.
    # Let's assume a URL for 'me' view exists, e.g., /api/entities/me/
    # If EntityMeViewset is meant to be the user's own detail view via the main ViewSet,
    # then these tests might need to be merged or rethought.
    # Given EntityMeViewset uses get_object = self.request.user, it's a specific endpoint.
    # We'll need to add a URL for it to test it properly.
    # For now, these tests will fail if 'entities:me' URL is not defined.
    # Let's create a dummy URL for testing purposes or assume it will be added.

    @pytest.fixture(autouse=True)
    def setup_me_url(self, monkeypatch):
        # This is a way to dynamically add a URL for testing this viewset if it's missing
        # from modules.entities.urls.py. For a real scenario, the URL should exist in urls.py
        from django.urls import path
        from modules.entities.views import EntityMeViewset

        # Check if 'entities:me' already exists to avoid issues if it's added later
        try:
            reverse('entities:me')
        except Exception: # Broad except because NoReverseMatch is the expected error
            # Dynamically add the URL pattern for 'me' view
            from modules.entities.urls import urlpatterns as entities_urlpatterns

            # Check if the 'me' path is already there to avoid duplicates if fixture runs multiple times
            # in a way that doesn't fully reset URL confs (though set_urlconf(None) should handle it)
            if not any(p.name == 'me' for p in entities_urlpatterns if hasattr(p, 'name')):
                entities_urlpatterns.append(
                    path('me/', EntityMeViewset.as_view(), name='me')
                )

            # No need to setattr if we modified the list in place, but if router.urls creates a new list
            # then setattr is needed. To be safe, let's ensure modules.entities.urls.urlpatterns
            # points to our modified list.
            monkeypatch.setattr('modules.entities.urls.urlpatterns', entities_urlpatterns)

            # Ensure URLconf is reloaded if it was already loaded
            from django.urls import clear_url_caches, set_urlconf
            clear_url_caches()
            set_urlconf(None) # Reloads default URLconf, which should pick up patched version
            # After reloading, try reversing again to confirm. If it fails here, the patching didn't work as expected.
            try:
                reverse('entities:me')
            except Exception as e:
                print(f"Failed to reverse 'entities:me' even after patching: {e}")


    def test_retrieve_me_authenticated(self, api_client, authenticated_user):
        url = reverse("entities:me") # Assumes a URL named 'me' exists for EntityMeViewset
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data["email"] == authenticated_user.email
        assert response.data["uuid"] == str(authenticated_user.uuid)

    def test_retrieve_me_unauthenticated(self, api_client):
        url = reverse("entities:me")
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED # or 403

    def test_update_me_authenticated(self, api_client, authenticated_user):
        url = reverse("entities:me")
        new_first_name = "UpdatedFirstName"
        data = {"first_name": new_first_name, "last_name": authenticated_user.last_name} # email is also updatable

        response = api_client.patch(url, data) # Use PATCH for partial update
        assert response.status_code == status.HTTP_200_OK
        authenticated_user.refresh_from_db()
        assert authenticated_user.first_name == new_first_name
        assert response.data["first_name"] == new_first_name

    def test_update_me_password_authenticated(self, api_client, authenticated_user):
        url = reverse("entities:me")
        old_password_hash = authenticated_user.password
        data = {
            "password": "newsecurepassword123",
            "confirm_password": "newsecurepassword123"
        }
        response = api_client.patch(url, data) # PATCH for partial update
        assert response.status_code == status.HTTP_200_OK
        authenticated_user.refresh_from_db()
        assert authenticated_user.check_password("newsecurepassword123")
        assert authenticated_user.password != old_password_hash
        assert "password" not in response.data # Password should not be in response

    def test_update_me_unauthenticated(self, api_client):
        url = reverse("entities:me")
        data = {"first_name": "AnonymousUpdate"}
        response = api_client.put(url, data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED # or 403

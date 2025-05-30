from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from model_bakery import baker
from django.contrib.auth import get_user_model

from modules.entities.models import Entity
from modules.entities.serializers import EntitySerializer, EntityMeSerializer

User = get_user_model()


class EntityViewSetTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = baker.make(User, is_staff=True)  # Staff user for full access
        self.client.force_authenticate(user=self.user)
        self.entity1 = baker.make(Entity, first_name="Test", last_name="User1")
        self.entity2 = baker.make(Entity, first_name="Another", last_name="Entity")
        self.list_url = reverse('entities:entity-list')
        self.detail_url = reverse('entities:entity-detail', kwargs={'pk': self.entity1.pk})

    def test_list_entities_authenticated(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), Entity.objects.count()) # Paginated

    def test_list_entities_unauthenticated(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_entity(self):
        data = {
            "first_name": "New",
            "last_name": "Entity",
            "email": "new.entity@example.com",
            "entity_type": "PSN",
            "password": "newpassword123",
            "confirm_password": "newpassword123"
        }
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Entity.objects.count(), 4) # 1 user + 2 entities + 1 new
        self.assertTrue(Entity.objects.filter(email="new.entity@example.com").exists())

    def test_retrieve_entity(self):
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        serializer = EntitySerializer(self.entity1)
        self.assertEqual(response.data, serializer.data)

    def test_update_entity(self):
        data = {"first_name": "Updated"}
        response = self.client.patch(self.detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.entity1.refresh_from_db()
        self.assertEqual(self.entity1.first_name, "Updated")

    def test_delete_entity(self):
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Entity.objects.filter(pk=self.entity1.pk).exists())
        self.assertEqual(Entity.objects.count(), 2) # 1 user + 1 entity remaining


class EntityMeViewsetTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = baker.make(User, first_name="Current", last_name="User", email="me@example.com")
        self.client.force_authenticate(user=self.user)
        self.me_url = reverse('entities:entity-me')

    def test_retrieve_me_authenticated(self):
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        serializer = EntityMeSerializer(self.user)
        # Compare relevant fields, as serializer might have more/less
        self.assertEqual(response.data['email'], serializer.data['email'])
        self.assertEqual(response.data['first_name'], serializer.data['first_name'])
        self.assertEqual(response.data['last_name'], serializer.data['last_name'])


    def test_retrieve_me_unauthenticated(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_me(self):
        data = {"first_name": "Updated Me", "last_name": "Also"}
        response = self.client.put(self.me_url, data) # PUT for full update
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Updated Me")
        self.assertEqual(self.user.last_name, "Also")

    def test_update_me_partial(self):
        data = {"first_name": "JustFirstName"}
        response = self.client.patch(self.me_url, data) # PATCH for partial
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "JustFirstName")
        # Last name should remain unchanged
        self.assertEqual(self.user.last_name, "User")

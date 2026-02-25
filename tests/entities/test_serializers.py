import pytest
from django.contrib.auth import get_user_model
from modules.entities.serializers import EntitySerializer

User = get_user_model()


@pytest.mark.django_db
class TestEntitySerializer:
    def test_validate_passwords_match(self):
        serializer = EntitySerializer(
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": "testuser@example.com",
                "password": "strongpassword123",
                "confirm_password": "strongpassword123",
            }
        )
        assert serializer.is_valid(), serializer.errors

    def test_validate_passwords_mismatch(self):
        serializer = EntitySerializer(
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": "testuser@example.com",
                "password": "strongpassword123",
                "confirm_password": "wrongpassword123",
            }
        )
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_create_with_password(self):
        serializer = EntitySerializer(
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": "testuser2@example.com",
                "password": "strongpassword123",
                "confirm_password": "strongpassword123",
            }
        )
        assert serializer.is_valid()
        user = serializer.save()
        assert user.check_password("strongpassword123")

    def test_update_without_password(self):
        user = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="testpass123",
        )
        serializer = EntitySerializer(
            instance=user,
            data={
                "first_name": "Marco Updated",
                "last_name": "Polo",
            },
            partial=True,
        )
        assert serializer.is_valid()
        updated_user = serializer.save()
        assert updated_user.first_name == "Marco Updated"

    def test_update_with_password(self):
        user = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="testpass123",
        )
        serializer = EntitySerializer(
            instance=user,
            data={"password": "newpassword123", "confirm_password": "newpassword123"},
            partial=True,
        )
        assert serializer.is_valid(), serializer.errors
        updated_user = serializer.save()
        assert updated_user.check_password("newpassword123")

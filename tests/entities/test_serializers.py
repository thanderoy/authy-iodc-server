import pytest
from rest_framework.exceptions import ValidationError
from model_bakery import baker

from modules.entities.models import Entity
from modules.entities.serializers import EntitySerializer, EntityMeSerializer

pytestmark = pytest.mark.django_db


class TestEntitySerializer:
    def test_serializer_valid_data_create_person(self):
        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "entity_type": "PSN",
            "password": "password123",
            "confirm_password": "password123",
        }
        serializer = EntitySerializer(data=data)
        assert serializer.is_valid(raise_exception=True)
        entity = serializer.save()
        assert entity.first_name == "Test"
        assert entity.email == "test@example.com"
        assert entity.entity_type == Entity.EntityType.PERSON
        assert entity.check_password("password123")
        assert entity.is_active is False # Default
        assert entity.is_system_entity is False # Default for PSN

    def test_serializer_valid_data_create_group(self):
        data = {
            "first_name": "Test",
            "last_name": "Group",
            "email": "group@example.com",
            "entity_type": "GRP",
            "password": "password123",
            "confirm_password": "password123",
        }
        serializer = EntitySerializer(data=data)
        assert serializer.is_valid(raise_exception=True)
        entity = serializer.save()
        assert entity.entity_type == Entity.EntityType.GROUP
        assert entity.is_system_entity is True # Default for non-PSN

    def test_serializer_invalid_password_mismatch(self):
        data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "entity_type": "PSN",
            "password": "password123",
            "confirm_password": "password456", # Mismatch
        }
        serializer = EntitySerializer(data=data)
        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "Passwords do not match." in str(excinfo.value)

    def test_serializer_missing_required_fields(self):
        # Test missing first_name
        data_no_first_name = {
            "last_name": "User", "email": "test@example.com", "entity_type": "PSN",
            "password": "pw", "confirm_password": "pw"
        }
        serializer_no_first_name = EntitySerializer(data=data_no_first_name)
        with pytest.raises(ValidationError) as excinfo:
            serializer_no_first_name.is_valid(raise_exception=True)
        assert "first_name" in excinfo.value.detail

        # Test missing email
        data_no_email = {
            "first_name": "Test", "last_name": "User", "entity_type": "PSN",
            "password": "pw", "confirm_password": "pw"
        }
        serializer_no_email = EntitySerializer(data=data_no_email)
        with pytest.raises(ValidationError) as excinfo:
            serializer_no_email.is_valid(raise_exception=True)
        assert "email" in excinfo.value.detail

        # Test missing password
        data_no_password = {
            "first_name": "Test", "last_name": "User", "email": "test@example.com", "entity_type": "PSN",
            "confirm_password": "pw"
        }
        serializer_no_password = EntitySerializer(data=data_no_password)
        with pytest.raises(ValidationError) as excinfo:
            serializer_no_password.is_valid(raise_exception=True)
        assert "password" in excinfo.value.detail

        # Test missing confirm_password
        data_no_confirm_password = {
            "first_name": "Test", "last_name": "User", "email": "test@example.com", "entity_type": "PSN",
            "password": "pw"
        }
        serializer_no_confirm_password = EntitySerializer(data=data_no_confirm_password)
        with pytest.raises(ValidationError) as excinfo:
            serializer_no_confirm_password.is_valid(raise_exception=True)
        assert "confirm_password" in excinfo.value.detail


    def test_serializer_update_entity(self):
        entity = baker.make(Entity, email="original@example.com", first_name="Original")
        data = {
            "first_name": "Updated",
            "last_name": entity.last_name, # Keep some original data
            "email": entity.email # Email shouldn't change in this partial update
        }
        serializer = EntitySerializer(instance=entity, data=data, partial=True)
        assert serializer.is_valid(raise_exception=True)
        updated_entity = serializer.save()
        assert updated_entity.first_name == "Updated"
        assert updated_entity.email == "original@example.com" # Ensure email is not changed by default

    def test_serializer_update_password(self):
        entity = baker.make(Entity, email="pwchange@example.com")
        old_password_hash = entity.password
        data = {
            "password": "newpassword123",
            "confirm_password": "newpassword123",
        }
        serializer = EntitySerializer(instance=entity, data=data, partial=True)
        assert serializer.is_valid(raise_exception=True)
        updated_entity = serializer.save()
        assert updated_entity.check_password("newpassword123")
        assert updated_entity.password != old_password_hash

    def test_serializer_update_password_invalid_validation(self):
        entity = baker.make(Entity, email="pw_validate_fail@example.com")
        data = {
            "password": "short", # Password that should fail Django's validation
            "confirm_password": "short",
        }
        serializer = EntitySerializer(instance=entity, data=data, partial=True)
        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        # Check that the error is from Django's password validation
        assert any("too short" in str(err) or "common" in str(err) for err_list in excinfo.value.detail.values() for err in err_list if isinstance(excinfo.value.detail, dict)) or \
               any("too short" in str(err) or "common" in str(err) for err in excinfo.value.detail if isinstance(excinfo.value.detail, list))


    def test_serializer_read_only_fields(self):
        entity = baker.make(Entity, email="readonly@example.com", is_active=False, is_system_entity=False)
        data = {
            "first_name": "TestRO",
            "last_name": "UserRO",
            "email": "readonly_create@example.com", # Must provide unique email for validation if not partial
            "entity_type": "PSN",
            "password": "password123",
            "confirm_password": "password123",
            # Attempt to write to read_only fields
            "uuid": "some-other-uuid",
            "is_active": True,
            "is_system_entity": True
        }
        # For create, read_only fields are ignored if passed
        serializer_create = EntitySerializer(data=data)
        assert serializer_create.is_valid(raise_exception=True)
        created_entity = serializer_create.save()
        assert str(created_entity.uuid) != "some-other-uuid" # Should be auto-generated
        assert created_entity.is_active is False # Should remain default or model-defined
        assert created_entity.is_system_entity is False

        # For update, read_only fields are ignored if passed
        update_data = {
            "first_name": "UpdatedRO",
            "uuid": "another-uuid",
            "is_active": True,
            "is_system_entity": True
        }
        serializer_update = EntitySerializer(instance=created_entity, data=update_data, partial=True)
        assert serializer_update.is_valid(raise_exception=True)
        updated_entity = serializer_update.save()
        assert updated_entity.first_name == "UpdatedRO"
        assert str(updated_entity.uuid) != "another-uuid" # Should not change
        assert updated_entity.is_active is False # Should not change
        assert updated_entity.is_system_entity is False # Should not change


class TestEntityMeSerializer:
    def test_me_serializer_valid_data(self):
        user = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="me@example.com")
        data = {
            "first_name": "MyNewName",
            "last_name": user.last_name, # Keep some original
            # email is not typically updated via "me" for this serializer, but let's test it
            "email": "me_new_email@example.com",
        }
        # Note: EntityMeSerializer doesn't enforce password/confirm_password if not provided
        # It inherits fields from EntitySerializer but typically used for Retrieve/Update
        serializer = EntityMeSerializer(instance=user, data=data, partial=True)
        assert serializer.is_valid(raise_exception=True)
        updated_user = serializer.save()
        assert updated_user.first_name == "MyNewName"
        assert updated_user.email == "me_new_email@example.com"

    def test_me_serializer_update_password(self):
        user = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="me_pw@example.com")
        old_password_hash = user.password
        data = {
            "password": "mynewpassword123",
            "confirm_password": "mynewpassword123",
        }
        serializer = EntityMeSerializer(instance=user, data=data, partial=True)
        assert serializer.is_valid(raise_exception=True)
        updated_user = serializer.save()
        assert updated_user.check_password("mynewpassword123")
        assert updated_user.password != old_password_hash

    def test_me_serializer_fields(self):
        # Check that the fields are as expected (subset of EntitySerializer for "me" context)
        # This is more of a sanity check for field listing in Meta
        user = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="me_fields@example.com")
        serializer = EntityMeSerializer(instance=user)
        data = serializer.data
        expected_fields = [
            "uuid", "first_name", "last_name", "email", "entity_type",
            # password and confirm_password are write_only, so not in output
            "is_active", "is_system_entity",
        ]
        for field in expected_fields:
            assert field in data
        assert "password" not in data # write_only
        assert "confirm_password" not in data # write_only

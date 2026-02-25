import pytest
from django.contrib.auth import get_user_model
from modules.entities.models import Entity

User = get_user_model()


@pytest.mark.django_db
class TestEntityModels:
    def test_person_manager(self):
        person = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="sys",
        )
        group = User.objects.create_user(
            first_name="Admin",
            last_name="Group",
            email="admin@example.com",
            password="sys",
            entity_type=Entity.EntityType.GROUP,
        )

        persons = Entity.persons.all()
        assert person in persons
        assert group not in persons

    def test_group_manager(self):
        person = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="sys",
        )
        group = User.objects.create_user(
            first_name="Admin",
            last_name="Group",
            email="admin@example.com",
            password="sys",
            entity_type=Entity.EntityType.GROUP,
        )

        groups = Entity.groups.all()
        assert group in groups
        assert person not in groups

    def test_entity_names_property(self):
        person = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="sys",
        )
        assert person.names == "Marco Polo"

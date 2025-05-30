import pytest
from django.db import IntegrityError
from django.core.exceptions import ValidationError as DjangoValidationError  # Renamed to avoid clash
from pytest_django.asserts import assertQuerySetEqual

from modules.entities.models import Entity, Relationship, EntityManager
from model_bakery import baker

pytestmark = pytest.mark.django_db

class TestEntityModel:
    def test_create_person_entity(self):
        person = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="test.person@example.com")
        assert str(person) == f"PSN ({person.id})- {person.first_name} {person.last_name}"
        assert person.is_system_entity is False
        assert Entity.persons.count() == 1
        assert Entity.groups.count() == 0

    def test_create_group_entity(self):
        group = baker.make(Entity, entity_type=Entity.EntityType.GROUP, email="test.group@example.com")
        assert str(group) == f"GRP ({group.id})- {group.first_name} {group.last_name}"
        assert group.is_system_entity is False # Default for baker creation if not specified
        assert Entity.groups.count() == 1
        assert Entity.persons.count() == 0

    def test_entity_names_property(self):
        entity = baker.make(Entity, first_name="John", last_name="Doe")
        assert entity.names == "John Doe"

    def test_email_is_unique(self):
        baker.make(Entity, email="unique@example.com")
        with pytest.raises(IntegrityError):
            baker.make(Entity, email="unique@example.com")

    def test_first_name_required(self):
        with pytest.raises(IntegrityError): # Django raises IntegrityError for missing NOT NULL fields at DB level
            baker.make(Entity, first_name=None, last_name="LN", email="fn@example.com")

    def test_last_name_required(self):
        with pytest.raises(IntegrityError):
            baker.make(Entity, last_name=None, first_name="FN", email="ln@example.com")

    def test_email_required(self):
        with pytest.raises(IntegrityError):
            baker.make(Entity, email=None, first_name="FN", last_name="LN")

class TestEntityManager:
    def test_create_user_person(self, django_user_model):
        manager = django_user_model.objects
        user = manager.create_user(
            first_name="Test",
            last_name="User",
            email="person@example.com",
            password="password123"
        )
        assert user.first_name == "Test"
        assert user.last_name == "User"
        assert user.email == "person@example.com"
        assert user.entity_type == Entity.EntityType.PERSON
        assert user.is_staff is False
        assert user.is_superuser is False
        assert user.is_system_entity is False
        assert user.check_password("password123")

    def test_create_user_group(self, django_user_model):
        manager = django_user_model.objects
        user = manager.create_user(
            first_name="Group",
            last_name="Test",
            email="group@example.com",
            password="password123",
            entity_type=Entity.EntityType.GROUP
        )
        assert user.entity_type == Entity.EntityType.GROUP
        assert user.is_system_entity is True # Non-person entities are system entities

    def test_create_superuser(self, django_user_model):
        manager = django_user_model.objects
        admin_user = manager.create_superuser(
            first_name="Super",
            last_name="User",
            email="admin@example.com",
            password="password123"
        )
        assert admin_user.email == "admin@example.com"
        assert admin_user.entity_type == Entity.EntityType.PERSON # Default for superuser
        assert admin_user.is_active is True
        assert admin_user.is_staff is True
        assert admin_user.is_superuser is True
        assert admin_user.is_system_entity is False
        assert admin_user.check_password("password123")

    def test_create_superuser_raises_error_if_is_staff_false(self, django_user_model):
        manager = django_user_model.objects
        with pytest.raises(ValueError, match="Superuser must have is_staff=True."):
            manager.create_superuser(
                first_name="Test", last_name="User", email="staff@example.com", password="password", is_staff=False
            )

    def test_create_superuser_raises_error_if_is_superuser_false(self, django_user_model):
        manager = django_user_model.objects
        with pytest.raises(ValueError, match="Superuser must have is_superuser=True."):
            manager.create_superuser(
                first_name="Test", last_name="User", email="super@example.com", password="password", is_superuser=False
            )

    def test_create_user_missing_fields(self, django_user_model):
        manager = django_user_model.objects
        with pytest.raises(ValueError, match="First Name is required."):
            manager.create_user(first_name="", last_name="User", email="test@example.com", password="password")
        with pytest.raises(ValueError, match="Last Name is required."):
            manager.create_user(first_name="Test", last_name="", email="test@example.com", password="password")
        with pytest.raises(ValueError, match="Email is required."):
            manager.create_user(first_name="Test", last_name="User", email="", password="password")

class TestPersonManager:
    def test_get_queryset(self):
        person1 = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="person1@example.com")
        person2 = baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="person2@example.com")
        baker.make(Entity, entity_type=Entity.EntityType.GROUP, email="group1@example.com")

        persons_qs = Entity.persons.all()
        assert persons_qs.count() == 2
        assertQuerySetEqual(persons_qs, [person1, person2], ordered=False, transform=lambda x: x)

class TestGroupManager:
    def test_get_queryset(self):
        group1 = baker.make(Entity, entity_type=Entity.EntityType.GROUP, email="group1@example.com")
        group2 = baker.make(Entity, entity_type=Entity.EntityType.GROUP, email="group2@example.com")
        baker.make(Entity, entity_type=Entity.EntityType.PERSON, email="person1@example.com")

        groups_qs = Entity.groups.all()
        assert groups_qs.count() == 2
        assertQuerySetEqual(groups_qs, [group1, group2], ordered=False, transform=lambda x: x)


class TestRelationshipModel:
    def test_create_relationship(self):
        parent_entity = baker.make(Entity, email="parent@example.com")
        child_entity = baker.make(Entity, email="child@example.com")
        relationship = baker.make(
            Relationship,
            parent=parent_entity,
            child=child_entity,
            relationship_type=Relationship.RelationshipType.MEMBER
        )
        assert str(relationship) == f"MEM - ({parent_entity} -> {child_entity})"
        assert relationship.parent == parent_entity
        assert relationship.child == child_entity
        assert relationship.relationship_type == Relationship.RelationshipType.MEMBER

    def test_relationship_default_type(self):
        relationship = baker.make(Relationship) # Let baker fill foreign keys
        assert relationship.relationship_type == Relationship.RelationshipType.UNDEFINED

    def test_entity_can_have_multiple_children(self):
        parent = baker.make(Entity, email="parent@example.com")
        child1 = baker.make(Entity, email="child1@example.com")
        child2 = baker.make(Entity, email="child2@example.com")

        baker.make(Relationship, parent=parent, child=child1)
        baker.make(Relationship, parent=parent, child=child2)

        assert parent.child_entities.count() == 2
        assert child1.parent_entities.count() == 1
        assert child1.parent_entities.first() == parent

    def test_entity_can_have_multiple_parents(self):
        child = baker.make(Entity, email="child@example.com")
        parent1 = baker.make(Entity, email="parent1@example.com")
        parent2 = baker.make(Entity, email="parent2@example.com")

        baker.make(Relationship, parent=parent1, child=child)
        baker.make(Relationship, parent=parent2, child=child)

        assert child.parent_entities.count() == 2
        assert parent1.child_entities.count() == 1
        assert parent1.child_entities.first() == child

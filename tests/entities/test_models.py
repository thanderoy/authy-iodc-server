from django.test import TestCase
from django.contrib.auth import get_user_model
from model_bakery import baker

from modules.entities.models import Entity, Relationship

User = get_user_model()


class EntityModelTests(TestCase):
    def test_create_person_entity(self):
        user = baker.make(User, entity_type=Entity.EntityType.PERSON)
        self.assertEqual(user.entity_type, Entity.EntityType.PERSON)
        self.assertEqual(Entity.persons.count(), 1)
        self.assertEqual(Entity.groups.count(), 0)

    def test_create_group_entity(self):
        group = baker.make(User, entity_type=Entity.EntityType.GROUP)
        self.assertEqual(group.entity_type, Entity.EntityType.GROUP)
        self.assertEqual(Entity.groups.count(), 1)
        self.assertEqual(Entity.persons.count(), 0)

    def test_entity_names_property(self):
        user = baker.make(User, first_name="John", last_name="Doe")
        self.assertEqual(user.names, "John Doe")

    def test_entity_str_method(self):
        user = baker.make(User, id=1, first_name="Jane", last_name="Doe", entity_type=Entity.EntityType.PERSON)
        self.assertEqual(str(user), "PSN (1)- Jane Doe")
        group = baker.make(User, id=2, first_name="Test", last_name="Group", entity_type=Entity.EntityType.GROUP)
        self.assertEqual(str(group), "GRP (2)- Test Group")

    def test_entity_managers(self):
        baker.make(User, entity_type=Entity.EntityType.PERSON, _quantity=3)
        baker.make(User, entity_type=Entity.EntityType.GROUP, _quantity=2)
        self.assertEqual(Entity.objects.count(), 5)
        self.assertEqual(Entity.persons.count(), 3)
        self.assertEqual(Entity.groups.count(), 2)


class RelationshipModelTests(TestCase):
    def setUp(self):
        self.person1 = baker.make(User, entity_type=Entity.EntityType.PERSON)
        self.person2 = baker.make(User, entity_type=Entity.EntityType.PERSON)
        self.group1 = baker.make(User, entity_type=Entity.EntityType.GROUP)

    def test_create_relationship(self):
        relationship = baker.make(
            Relationship,
            parent=self.group1,
            child=self.person1,
            relationship_type=Relationship.RelationshipType.MEMBER
        )
        self.assertEqual(Relationship.objects.count(), 1)
        self.assertEqual(relationship.parent, self.group1)
        self.assertEqual(relationship.child, self.person1)
        self.assertEqual(relationship.relationship_type, Relationship.RelationshipType.MEMBER)

    def test_relationship_str_method(self):
        relationship = baker.make(
            Relationship,
            parent=self.group1,
            child=self.person1,
            relationship_type=Relationship.RelationshipType.MEMBER
        )
        expected_str = f"MEM - ({self.group1} -> {self.person1})"
        self.assertEqual(str(relationship), expected_str)

    def test_relationship_undefined_type_default(self):
        relationship = baker.make(
            Relationship,
            parent=self.group1,
            child=self.person2
        )
        self.assertEqual(relationship.relationship_type, Relationship.RelationshipType.UNDEFINED)

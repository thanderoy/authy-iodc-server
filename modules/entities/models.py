from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, \
    PermissionsMixin
from django.db import models

from modules.common.models import AuthyBaseModel


class EntityManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, first_name, last_name, email, password, entity_type="PSN", **extra_fields):  # noqa
        if not first_name:
            raise ValueError("First Name is required.")
        if not last_name:
            raise ValueError("Last Name is required.")
        if not email:
            raise ValueError("Email is required.")
        # Non-Person enitities are not allowed to login only used
        #    for communication and entity management. No pass expiry
        if entity_type != self.model.EntityType.PERSON:
            extra_fields["is_system_entity"] = True

        email = self.normalize_email(email)
        user = self.model(
            first_name=first_name, last_name=last_name, email=email,
            entity_type=entity_type, **extra_fields
        )
        user.set_password(password)
        user.save()
        return user

    def create_user(self, first_name, last_name, email, password, entity_type="PSN", **extra_fields):   # noqa
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)

        return self._create_user(
            first_name, last_name, email, password, entity_type, **extra_fields)    # noqa

    def create_superuser(self, first_name, last_name, email, password, entity_type="PSN", **extra_fields):   # noqa
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(
            first_name, last_name, email, password, entity_type, **extra_fields)    # noqa


class PersonManager(EntityManager):

    def get_queryset(self):

        return self.model.filter(entity_type=self.model.EntityType.PERSON)


class GroupManager(EntityManager):

    def get_queryset(self):

        return self.model.filter(entity_type=self.model.EntityType.GROUP)



class Entity(AuthyBaseModel, AbstractBaseUser, PermissionsMixin):
    class EntityType(models.TextChoices):
        PERSON = "PSN", "Person"
        GROUP = "GRP", "Group"

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ('first_name', 'last_name', )

    # Entity details
    first_name = models.CharField(max_length=50, blank=False, null=False)
    last_name = models.CharField(max_length=50, blank=False, null=False)
    entity_type = models.CharField(
        choices=EntityType.choices, max_length=3, default=EntityType.PERSON)
    email = models.EmailField(max_length=255, unique=True, blank=False, null=False) # noqa

    # Access + Priviledges
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_system_entity = models.BooleanField(default=False)

    # Relationships
    child_entities = models.ManyToManyField(
        "self", through="Relationship", symmetrical=False, related_name="parent_entities")  # noqa: E501

    # Managers
    objects = EntityManager()
    persons = PersonManager()
    groups = GroupManager()

    class Meta(object):
        ordering = ("first_name", "last_name",)

    @property
    def names(self):
        return f"{self.first_name} {self.last_name}"

    def __str__(self) -> str:
        return f"{self.entity_type} ({self.id})- {self.names}"


class Relationship(AuthyBaseModel):
    class RelationshipType(models.TextChoices):
        UNDEFINED = "UND", "Undefined"
        MEMBER = "MEM", "Member"

    parent = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name='parent_relations')
    child = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name='child_relations')
    relationship_type = models.CharField(
        RelationshipType.choices, max_length=50, default=RelationshipType.UNDEFINED)    # noqa: E501

    def __str__(self) -> str:
        return f"{self.relationship_type} - ({self.parent} -> {self.child})"
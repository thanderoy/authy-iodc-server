import uuid

from django.db import models


class AuthyBaseModel(models.Model):
    """
    Contains global default attributes.
    """
    uuid = models.UUIDField(
        default=uuid.uuid4, editable=False, unique=True)
    created = models.DateTimeField(
        auto_now_add=True, db_index=True, editable=False)
    updated = models.DateTimeField(
        auto_now=True, db_index=True, editable=False)

    class Meta:
        abstract = True
        ordering = ("-updated", "-created")
        indexes = [
            models.Index(fields=['-created']),
        ]

from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from rest_framework.exceptions import ValidationError
from modules.entities.models import Entity

USER_MODEL = get_user_model()


class EntitySerializer(serializers.ModelSerializer):

    confirm_password = serializers.CharField(write_only=True, required=True)
    organizations = serializers.PrimaryKeyRelatedField(
        queryset=Entity.objects.filter(
            entity_type=Entity.EntityType.ORGANIZATION), many=True, required=False  # noqa
        )
    # parent_entities = serializers.StringRelatedField(many=True)

    class Meta:
        model = USER_MODEL
        fields = (
            "uuid", "first_name", "last_name", "email", "entity_type",
            "password", "confirm_password", "is_active", "is_system_entity",
        )
        read_only_fields = ("uuid", "is_active", "is_system_entity")
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        super(EntitySerializer, self).validate(attrs)
        if 'confirm_password' in attrs or 'password' in attrs:
            confirm_password = attrs.get('confirm_password', None)
            password = attrs.get('password', None)
            if password != confirm_password:
                raise ValidationError(
                    "Passwords do not match."
                )
            if self.instance:
                password_validation.validate_password(password, self.instance)
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = super().create(validated_data)
        if password is not None:
            instance.set_password(password)
            instance.save()
        return instance

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
            validated_data.pop('confirm_password')
            validated_data.pop('password')
        return super(EntitySerializer, self).update(instance, validated_data)


class EntityMeSerializer(EntitySerializer):
    """
    Serializer for the user data endpoint. Currently logged in user.

    Allows for updating:
        - First name
        - Last name
        - Email
        - Password
    """
    class Meta(EntitySerializer.Meta):
        fields = (
            "uuid", "first_name", "last_name", "email", "entity_type",
            "password", "confirm_password", "is_active", "is_system_entity",
        )

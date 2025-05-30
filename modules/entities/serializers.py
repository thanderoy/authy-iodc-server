from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from rest_framework.exceptions import ValidationError
from modules.entities.models import Entity

USER_MODEL = get_user_model()


class EntitySerializer(serializers.ModelSerializer):

    confirm_password = serializers.CharField(write_only=True, required=False) # Changed to required=False
    # organizations = serializers.PrimaryKeyRelatedField(
    #     queryset=Entity.objects.filter(
    #         entity_type=Entity.EntityType.ORGANIZATION), many=True, required=False  # noqa
    #     )
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
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password or confirm_password: # Only validate if either is present
            if password != confirm_password:
                raise ValidationError("Passwords do not match.")
            # Validate password strength only if it's being set (create or update)
            # For updates (self.instance is not None), this applies if password is in attrs.
            # For creates, this applies if password is in attrs.
            if password: # Ensure password is not empty if provided
                 password_validation.validate_password(password, self.instance if self.instance else None)
            elif not self.instance and not password : # Required on create if not provided
                 raise ValidationError({"password": ["This field is required."]})


        # If this is a create operation (no instance) and password is not provided,
        # it should have been caught by field-level validation if password was required=True.
        # If password field itself is required=False (e.g. for updates), this logic is fine.
        # Current password field is write_only=True, implicitly required=True for ModelSerializer create.

        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        validated_data.pop("confirm_password", None) # Remove confirm_password before creating user
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
    class Meta:
        model = USER_MODEL # Explicitly set model
        fields = (
            "uuid", "first_name", "last_name", "email",
            "password", "confirm_password", # Password fields for update
            "entity_type", "is_active", "is_system_entity" # Read-only typically
        )
        read_only_fields = (
            "uuid", "email", "entity_type", # Email often used as username, treat as read-only here or require re-auth/verification
            "is_active", "is_system_entity"
        )
        extra_kwargs = {
            "password": {"write_only": True, "required": False, "allow_null": True},
            "confirm_password": {"write_only": True, "required": False, "allow_null": True},
            "first_name": {"required": False}, # Allow partial updates even with PUT for these
            "last_name": {"required": False},
        }

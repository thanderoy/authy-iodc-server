from django.contrib.auth.forms import UserCreationForm
from django import forms
from modules.entities.models import Entity


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):  # type: ignore
        model = Entity
        fields = ("first_name", "last_name", "email")


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = Entity
        fields = ("first_name", "last_name")

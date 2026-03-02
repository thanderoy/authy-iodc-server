from django.contrib import admin
from modules.entities.models import ApplicationBranding


@admin.register(ApplicationBranding)
class ApplicationBrandingAdmin(admin.ModelAdmin):
    list_display = ("application", "brand_color", "logo_url")
    search_fields = ("application__name",)

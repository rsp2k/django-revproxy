from django.apps import apps
from django.conf import settings
from django.contrib import admin
from django.contrib.admin.exceptions import AlreadyRegistered


from .models import CachedResponse


@admin.register(CachedResponse)
class CachedResponseAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'request_host', 'request_path', 'request_method', 'response_status_code', 'response_content_type')


if True and settings.DEBUG:
    # Auto register all unregistered models in this app
    app_models = apps.get_app_config("revproxy").get_models()
    for model in app_models:
        try:
            admin.site.register(model)
        except AlreadyRegistered:
            pass
from django.apps import apps
from django.conf import settings
from django.contrib import admin


from .models import CachedResponse

@admin.register(CachedResponse)
class CachedResponseAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'img_tag', 'request_host', 'request_path', 'request_method', 'response_status_code', 'response_content_type')


def register_all_models(app_name):
    app_models = apps.get_app_config(app_name).get_models()
    for model in app_models:
        try:
            admin.site.register(model)
        except AlreadyRegistered:
            pass


register_all_models("revproxy")

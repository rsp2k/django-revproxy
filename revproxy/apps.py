from django.apps import AppConfig

from revproxy import app_settings

class RevproxyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "revproxy"

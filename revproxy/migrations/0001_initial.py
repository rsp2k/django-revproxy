# Generated by Django 5.0.4 on 2024-05-07 02:15

import revproxy.models
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CachedResponse",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "request_md5",
                    models.CharField(db_index=True, editable=False, max_length=32),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "last_accessed_at",
                    models.DateTimeField(auto_now=True, db_index=True),
                ),
                ("request_ip", models.GenericIPAddressField(db_index=True)),
                ("request_method", models.CharField(max_length=16)),
                (
                    "request_host",
                    models.CharField(db_index=True, max_length=500, null=True),
                ),
                ("request_path", models.CharField(max_length=200)),
                ("request_headers", models.JSONField()),
                ("request_body", models.TextField()),
                ("response_time", models.DurationField()),
                (
                    "response_status_code",
                    models.PositiveSmallIntegerField(db_index=True),
                ),
                ("response_headers", models.JSONField()),
                ("response_content_type", models.CharField(max_length=200)),
                ("response_body", models.TextField(null=True)),
                (
                    "response_data",
                    models.FileField(
                        null=True, upload_to=revproxy.models.response_data_directory_path
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at",),
            },
        ),
    ]

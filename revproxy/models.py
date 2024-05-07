import uuid

from django.db import models
from django.db.models import Q
from django.http import HttpResponse

from django.conf import settings
from revproxy import app_settings as revproxy_app_settings

import logging

logger = logging.getLogger(__name__)


class CachedResponseQuerySet(models.QuerySet):
    def valid_cache_responses(self, hash):
        return self.filter(request_md5=hash) & self.successfuls() & self.permanent_redirects()

    def informationals(self):
        return self.filter(
            Q(
                response_status_code__gte=100,
                response_status_code__lte=199,
            )
        )

    def successfuls(self):
        return self.filter(
            Q(
                response_status_code__gte=200,
                response_status_code__lte=299,
            )
        )

    def redirects(self):
        return self.permanent_redirects() | self.temporary_redirects()

    def permanent_redirects(self):
        return self.filter(
           response_status_code__in=[301, 308]
        )

    def temporary_redirects(self):
        return self.filter(
           response_status_code__in=[300, 302, 303, 304, 305, 306, 307, 308]
        )

    def client_errors(self):
        return self.filter(
            Q(
                response_status_code__gte=400,
                response_status_code__lte=499,
            )
        )

    def server_errors(self):
        return self.filter(
            Q(
                response_status_code__gte=500,
                response_status_code__lte=599,
            )
        )


class CachedResponse(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_md5 = models.CharField(
        max_length=128, db_index=True, editable=False
    )

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_accessed_at = models.DateTimeField(auto_now=True, db_index=True)

    request_ip = models.GenericIPAddressField(
        db_index=True,
    )

    request_method = models.CharField(
        max_length=16
    )

    request_host = models.CharField(
        max_length=500, db_index=True, null=True
    )

    request_path = models.CharField(max_length=200)

    request_headers = models.JSONField()
    request_body = models.TextField()

    response_time = models.DurationField()
    response_status_code = models.PositiveSmallIntegerField(db_index=True)

    response_headers = models.JSONField()
    response_content_type = models.CharField(max_length=200)

    response_body = models.TextField(null=True)
    response_data = models.BinaryField(null=True)

    objects = CachedResponseQuerySet.as_manager()

    class Meta:
        ordering = ('-created_at',)

    @property
    def request(self):
        raise NotImplementedError()

    @request.setter
    def request(self, request):
        self.request_ip = request.META.get('REMOTE_ADDR', None)
        self.request_host = request.get_host()
        self.request_path = request.path
        self.request_headers = dict(request.headers)
        self.request_body = request.body.decode('utf-8')
        self.request_method = request.method

    @property
    def response(self):
        return HttpResponse(
            content=self.response_body,
            headers=self.response_headers,
            status=self.response_status_code,
        )

    @response.setter
    def response(self, response_object):
        self.response_status_code = response_object.status_code
        self.response_headers = dict(response_object.headers)
        self.response_content_type = response_object.headers.get('Content-Type')
        self.response_body = getattr(response_object, 'text', None)
        self.response_data = getattr(response_object, 'content', None)

        return

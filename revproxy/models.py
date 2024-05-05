import json
import pickle
from copy import deepcopy

from django.db import models
from django.http import HttpResponse


class CachedResponse(models.Model):
    request_md5 = models.CharField(
        max_length=128, primary_key=True, db_index=True, editable=False
    )

    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed_at = models.DateTimeField(auto_now=True)

    request_ip = models.GenericIPAddressField(
        db_index=True,
    )

    request_method = models.CharField(max_length=16)
    request_host = models.CharField(max_length=500, db_index=True, null=True)
    request_path = models.CharField(max_length=200)
    request_headers = models.JSONField()
    request_body = models.TextField()

    response_status_code = models.PositiveSmallIntegerField()
    response_headers = models.JSONField()
    response_body = models.TextField()
    response_content_type = models.CharField(max_length=200)

    response_time = models.DurationField()

    @property
    def request(self):
        raise NotImplementedError()

    @request.setter
    def request(self, request):
        self.request_ip = request.META.get('REMOTE_ADDR')
        self.request_host = request.get_host()
        self.request_path = request.path
        self.request_headers = dict(request.headers)
        self.request_body = request.body.decode('utf-8')
        self.request_content_type = request.method
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
        self.response_body = response_object.text

        self.response_headers = dict(response_object.headers)
        self.response_content_type = response_object.headers.get('content-type', 'application/octet-stream')

        return


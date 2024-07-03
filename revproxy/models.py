import os
import pprint as pp
import hashlib
import uuid
from textwrap import wrap

import requests
import responses
from django.db import models
from django.db.models import Q
from django.http import HttpResponse, HttpRequest

from django.conf import settings
from django.utils.safestring import mark_safe
from requests.utils import stream_decode_response_unicode

from revproxy import app_settings as revproxy_app_settings

import logging


logger = logging.getLogger(__name__)


def response_data_directory_path(request_hash):
    # Split up hash into directories for filesystem relief
    # xxxxxxxx/xxxxxxxx/xxxxxxxx/xxxxxxxx

    dir_name = '/'.join(
        wrap(
            request_hash, 8
        ))

    upload_to_dir = f"cached_responses/{dir_name}/"
    logger.debug(f"{upload_to_dir=}")
    return upload_to_dir


def is_binary_content_type(content_type: str):
    mime_type, subtype = content_type.split('/')

    if mime_type == "text":
        return False
    if mime_type != "application":
        return True
    return subtype not in ["json", "ld+json", "x-httpd-php", "x-sh", "x-csh", "xhtml+xml", "xml"]


class ChunkReader:

    file = None

    def __init__(self, file):
        self.file = file

    def read(self, chunk_size):
        logger.debug(f"Reading chunk {chunk_size}")
        return self.file.read(chunk_size)


class CachedResponseQuerySet(models.QuerySet):
    def valid_cache_responses(self, hash):
        return (self.filter(
            request_md5=hash) &
            (self.successfuls() | self.permanent_redirects())
        )

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


class StreamableResponse(responses.Response):

    @property
    def iter_content(self, chunk_size=1, decode_unicode=False):
        """
        Return iterator over response content.
        """

        logger.debug(f"Streamable response! {self.body}")

        content = self.body.read(chunk_size)
        if decode_unicode:
            content = stream_decode_response_unicode(content, self)
            content = content.decode('utf-8')
        return content


class CachedResponse(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_md5 = models.CharField(
        max_length=32, db_index=True, editable=False
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
    response_data = models.FileField(
        upload_to=response_data_directory_path,
        null=True
    )

    objects = CachedResponseQuerySet.as_manager()

    class Meta:
        ordering = ('-created_at',)

    @property
    def request(self):
        raise NotImplementedError()

    @request.setter
    def request(self, request: HttpRequest):
        self.request_ip = request.META.get('REMOTE_ADDR', None)
        self.request_host = request.get_host()
        self.request_path = request.path
        self.request_headers = dict(request.headers)
        self.request_body = request.body.decode('utf-8')
        self.request_method = request.method

    @property
    def response(self) -> requests.Response:
        r = requests.Response()

        r.method = self.request_method
        r.url = self.request_host + self.request_path
        r.headers = self.response_headers
        r.content_type = self.response_content_type
        r.status_code = self.response_status_code
#        print(dir(self.response_data.file.file))
        r.raw = self.response_data.file
        r.stream = True,
#        r._contents = self.response_data

        return r

    @response.setter
    def response(self, response_object):
        self.response_status_code = response_object.status_code
        self.response_headers = dict(response_object.headers)
        self.response_content_type = response_object.headers.get('Content-Type')

        base_path = response_data_directory_path(self.request_md5)
        body_file = os.path.join(base_path, '_body')

        filename = os.path.basename(response_object.url)
        if '.' in filename:
            linked_filename = os.path.join(base_path, filename)
            os.symlink(
                os.path.join(settings.MEDIA_ROOT, body_file),
                os.path.join(settings.MEDIA_ROOT, linked_filename),
            )
            self.response_data.name = linked_filename
        else:
            self.response_data.name = body_file

        if not is_binary_content_type(self.response_content_type):
            self.response_body = response_object.text
        return

    @property
    def iter_content(self, chunk_size=1, decode_unicode=False) -> bytes:
        """
        Return bytes of response content.
        """

        logger.debug(f"iter_content {self.response_data.file}")

        content = self.response_data.file.chunks(chunk_size)
        if decode_unicode:
            content = content.decode('utf-8')
        return content

    def img_tag(self):
        mime_type, mime_subtype = self.response_content_type.split('/')
        if mime_type == 'image':
#            if mime_subtype.startswith('svg'):
#                return mark_safe(f"{self.response.data}")
            return mark_safe(f'<img width="150" src="{self.response_data.url}" />')

    img_tag.short_description = 'Thumbnail'
    img_tag.allow_tags = True


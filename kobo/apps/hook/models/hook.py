# -*- coding: utf-8 -*-
from importlib import import_module

from django.db import models
from django.utils import timezone
from jsonbfield.fields import JSONField as JSONBField

from ..constants import HOOK_LOG_PENDING, HOOK_LOG_FAILED, HOOK_LOG_SUCCESS
from kpi.fields import KpiUidField


class Hook(models.Model):

    # Export types
    XML = "xml"
    JSON = "json"

    # Authentication levels
    NO_AUTH = "no_auth"
    BASIC_AUTH = "basic_auth"

    # Export types list
    EXPORT_TYPE_CHOICES = (
        (XML, XML),
        (JSON, JSON)
    )

    # Authentication levels list
    AUTHENTICATION_LEVEL_CHOICES = (
        (NO_AUTH, NO_AUTH),
        (BASIC_AUTH, BASIC_AUTH)
    )

    asset = models.ForeignKey("kpi.Asset", related_name="hooks", on_delete=models.CASCADE)
    uid = KpiUidField(uid_prefix="h")
    name = models.CharField(max_length=255, blank=False)
    endpoint = models.CharField(max_length=500, blank=False)
    active = models.BooleanField(default=True)
    export_type = models.CharField(choices=EXPORT_TYPE_CHOICES, default=JSON, max_length=10)
    auth_level = models.CharField(choices=AUTHENTICATION_LEVEL_CHOICES, default=NO_AUTH, max_length=10)
    settings = JSONBField(default=dict)
    date_created = models.DateTimeField(default=timezone.now)
    date_modified = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name"]

    def __init__(self, *args, **kwargs):
        self.__totals = {}
        return super(Hook, self).__init__(*args, **kwargs)

    def save(self, *args, **kwargs):
        # Update date_modified each time object is saved
        self.date_modified = timezone.now()
        super(Hook, self).save(*args, **kwargs)

    def __unicode__(self):
        return u"%s:%s - %s" % (self.asset, self.name, self.endpoint)

    def get_service_definition(self):
        mod = import_module("kobo.apps.hook.services.service_{}".format(self.export_type))
        return getattr(mod, "ServiceDefinition")

    @property
    def success_count(self):
        if not self.__totals:
            self._get_totals()
        return self.__totals.get(HOOK_LOG_SUCCESS)

    @property
    def failed_count(self):
        if not self.__totals:
            self._get_totals()
        return self.__totals.get(HOOK_LOG_FAILED)

    @property
    def pending_count(self):
        if not self.__totals:
            self._get_totals()
        return self.__totals.get(HOOK_LOG_PENDING)

    def _get_totals(self):
        # TODO add some cache
        queryset = self.logs.values("status").annotate(values_count=models.Count("status"))
        queryset.query.clear_ordering(True)

        # Initialize totals
        self.__totals = {
            HOOK_LOG_SUCCESS: 0,
            HOOK_LOG_FAILED: 0,
            HOOK_LOG_PENDING: 0
        }
        for record in queryset:
            self.__totals[record.get("status")] = record.get("values_count")

    def reset_totals(self):
        # TODO remove cache when it's enabled
        self.__totals = {}
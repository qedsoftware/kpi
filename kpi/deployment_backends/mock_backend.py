#!/usr/bin/python
# -*- coding: utf-8 -*-

from base_backend import BaseDeploymentBackend
from kpi.constants import INSTANCE_FORMAT_TYPE_JSON, INSTANCE_FORMAT_TYPE_XML
from kpi.exceptions import BadFormatException


class MockDeploymentBackend(BaseDeploymentBackend):
    '''
    only used for unit testing and interface testing.

    defines the interface for a deployment backend.
    '''
    def connect(self, active=False):
        self.store_data({
                'backend': 'mock',
                'identifier': 'mock://%s' % self.asset.uid,
                'active': active,
            })

    def redeploy(self, active=None):
        '''
        Replace (overwrite) the deployment, keeping the same identifier, and
        optionally changing whether the deployment is active
        '''
        if active is None:
            active = self.active
        self.set_active(active)

    def set_active(self, active):
        self.store_data({
                'active': bool(active),
            })

    def get_enketo_survey_links(self):
        # `self` is a demo Enketo form, but there's no guarantee it'll be
        # around forever.
        return {
            'offline_url': 'https://enke.to/_/#self',
            'url': 'https://enke.to/::self',
            'iframe_url': 'https://enke.to/i/::self',
            'preview_url': 'https://enke.to/preview/::self',
            # 'preview_iframe_url': 'https://enke.to/preview/i/::self',
        }

    def get_data_download_links(self):
        return {}

    def _submission_count(self):
        submissions = self.asset._deployment_data.get('submissions', [])
        return len(submissions)

    def _mock_submission(self, submission):
        submissions = self.asset._deployment_data.get('submissions', [])
        submissions.append(submission)
        self.store_data({
            'submissions': submissions,
            })

    def get_submissions(self, format_type=INSTANCE_FORMAT_TYPE_JSON, instances_uuids=[]):
        """
        Returns a list of json representation of instances.

        :param format: str. xml or json
        :param instances_ids: list. Ids of instances to retrieve
        :return: list
        """
        if format_type == INSTANCE_FORMAT_TYPE_XML:
            raise BadFormatException("XML is not supported")
        else:
            submissions = self.asset._deployment_data.get("submissions", [])
            if len(instances_uuids) > 0:
                # Cast in str because uuid is a 36 alphanumeric string
                instances_uuids = [str(instance_uuid) for instance_uuid in instances_uuids]
                submissions = [submission for submission in submissions if str(submission.get("id")) in instances_uuids]

            return submissions

    def get_submission(self, pk, format_type=INSTANCE_FORMAT_TYPE_JSON):
         return self.get_submissions(format_type=format_type, instances_uuids=[pk])[0]

    def set_has_kpi_hooks(self):
        """
        Store results in self.asset._deployment_data
        """
        has_active_hooks = self.asset.has_active_hooks
        self.store_data({
            "has_kpi_hooks": has_active_hooks,
        })
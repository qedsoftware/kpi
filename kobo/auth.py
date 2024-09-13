import json
import logging

from collections import defaultdict
from django.conf import settings
from django.contrib.auth.middleware import RemoteUserMiddleware
from kpi.models import Asset
from kpi.models.object_permission import get_objects_for_user


class QedAuthMiddleware(RemoteUserMiddleware):
    header = 'HTTP_X_AUTH_USERNAME'


class QedRemoteUserAttributeMiddleware(object):
    username_header = 'HTTP_X_AUTH_USERNAME'
    email_header = 'HTTP_X_AUTH_EMAIL'
    roles_header = 'HTTP_X_AUTH_ROLES'

    def process_request(self, request):
        username = request.META.get(self.username_header, None)
        email = request.META.get(self.email_header, None)
        roles_json = request.META.get(self.roles_header, None)

        remote_user_ok = hasattr(request, 'user') and request.user.is_authenticated \
            and username and email

        if not remote_user_ok:
            return

        user = request.user

        QedRemoteUserAttributeMiddleware.process_user(user, email)
        QedRemoteUserAttributeMiddleware.process_roles(user, roles_json)

    @staticmethod
    def process_user(user, email):
        needs_saving = False

        if user.email != email:
            user.email = email
            needs_saving = True

        if needs_saving:
            user.save()

    @staticmethod
    def process_roles(user, roles_json):
        if not settings.USE_REMOTE_PERMS:
            return

        PERMS_MAP = {
            'form_view': 'view_asset',
            'form_edit': 'change_asset',
            'data_submit': 'add_submissions',
            'data_view': 'view_submissions',
            'data_edit': 'change_submissions',
        }

        logger = logging.getLogger("console_logger")

        if roles_json is None:
            raise RuntimeError("Remote perms enabled, but header not found")

        # KT__${var.kt_form_id}__${var.kt_form_permission}
        roles = json.loads(roles_json)

        kt_roles = defaultdict(set)
        for r in roles:
            if not r.startswith('KT__'):
                continue

            _, form_id, perm = r.split('__')

            if perm not in PERMS_MAP.keys():
                continue

            kt_roles[form_id].add(PERMS_MAP[perm])

        existing_roles = defaultdict(set)
        for perm_name in PERMS_MAP.values():
            for form_id in get_objects_for_user(user, perm_name, Asset).values_list("uid", flat=True):
                existing_roles[form_id].add(perm_name)

        for form_id in set(existing_roles.keys()) | set(kt_roles.keys()):
            try:
                asset = Asset.objects.get(uid=form_id)
            except MultipleObjectsReturned:
                logger.warning("Multiple forms with uid {}. This is not supported"
                               " for remote permissions management to avoid unexpected"
                               " sharing. Skipping.".format(form_id))
                continue

            current_perms = existing_roles[asset.uid]
            target_perms = kt_roles[asset.uid]

            to_remove = current_perms - target_perms
            to_add = target_perms - current_perms

            if len(to_remove) + len(to_add) > 0:
                logger.info("[{}] User {}, form {} ({}). Remove: {}, add: {}".format(
                    "perms_dry_run" if settings.REMOTE_PERMS_DRY_RUN else "perms",
                    user.username,
                    asset.name,
                    asset.uid,
                    str(to_remove),
                    str(to_add)
                ))

            if settings.REMOTE_PERMS_DRY_RUN:
                continue

            map(lambda p: asset.remove_perm(user, p), to_remove)
            map(lambda p: asset.assign_perm(user, p), to_add)

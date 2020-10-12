from django.contrib.auth.middleware import RemoteUserMiddleware


class QedAuthMiddleware(RemoteUserMiddleware):
    header = 'HTTP_X_AUTH_USERNAME'


class QedRemoteUserAttributeMiddleware(object):
    username_header = 'HTTP_X_AUTH_USERNAME'
    email_header = 'HTTP_X_AUTH_EMAIL'

    def process_request(self, request):
        username = request.META.get(self.username_header, None)
        email = request.META.get(self.email_header, None)

        if hasattr(request, 'user') and request.user.is_authenticated and \
                username and email:
            user = request.user
            needs_saving = False

            if user.email != email:
                user.email = email
                needs_saving = True

            if needs_saving:
                user.save()

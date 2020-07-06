from django.contrib.auth.middleware import RemoteUserMiddleware


class QedAuthMiddleware(RemoteUserMiddleware):
    header = 'HTTP_X_AUTH_USERNAME'

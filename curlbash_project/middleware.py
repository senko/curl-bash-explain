from django.http import HttpResponsePermanentRedirect

CANONICAL_HOST = 'curl-bash-explain.dev'


class WwwRedirectMiddleware:
    """Redirect www.curl-bash-explain.dev → curl-bash-explain.dev"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(':')[0]
        if host == f'www.{CANONICAL_HOST}':
            return HttpResponsePermanentRedirect(
                f'https://{CANONICAL_HOST}{request.get_full_path()}'
            )
        return self.get_response(request)

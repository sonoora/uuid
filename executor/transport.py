"""Bounded HTTPS, no redirects and no implicit retries or logging of request bodies."""
import json
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_json(url, body, headers):
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **headers}, method="POST")
    return send(request)


def get_json(url, headers):
    return send(urllib.request.Request(url, headers=headers, method="GET"))


def send(request):
    opener = urllib.request.build_opener(NoRedirect)
    try:
        response = opener.open(request, timeout=12)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("PROVIDER_RESULT_TOO_LARGE")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("PROVIDER_RESULT_INVALID")
        return response.status, payload

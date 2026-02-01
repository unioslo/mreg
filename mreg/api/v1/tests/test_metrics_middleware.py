from django.test import TestCase, RequestFactory
from django.http import HttpResponse, StreamingHttpResponse

from mreg.middleware.metrics import PrometheusRequestMiddleware


class MetricsMiddlewareResponseSizeTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_response_size_header_observed(self):
        request = self.factory.get("/api/v1/hosts/")
        response = HttpResponse("ok")
        response["Content-Length"] = "2"

        middleware = PrometheusRequestMiddleware(lambda _: response)
        middleware._normalize_path = lambda _: "test"  # type: ignore[assignment]

        middleware(request)

    def test_streaming_response_skips_size(self):
        request = self.factory.get("/api/v1/hosts/")
        response = StreamingHttpResponse(iter([b"chunk"]))

        middleware = PrometheusRequestMiddleware(lambda _: response)
        middleware._normalize_path = lambda _: "test"  # type: ignore[assignment]

        middleware(request)

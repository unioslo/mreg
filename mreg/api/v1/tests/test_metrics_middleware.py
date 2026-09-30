from django.test import RequestFactory, SimpleTestCase, TestCase
from django.http import HttpResponse, StreamingHttpResponse

from mreg.middleware.metrics import PrometheusRequestMiddleware


class MetricsMiddlewareUnitTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_unresolved_path_uses_bounded_label(self):
        middleware = PrometheusRequestMiddleware(lambda _: HttpResponse())
        request = self.factory.get("/not/a/real/path")

        self.assertEqual(middleware._normalize_path(request), "unresolved")

    def test_metrics_endpoint_bypasses_instrumentation(self):
        response = HttpResponse("metrics")
        middleware = PrometheusRequestMiddleware(lambda _: response)
        request = self.factory.get("/api/meta/metrics")

        self.assertIs(middleware(request), response)


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

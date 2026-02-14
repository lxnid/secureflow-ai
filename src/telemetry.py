"""OpenTelemetry instrumentation for SecureFlow AI.

Sets up distributed tracing with Azure Monitor export.
Provides a tracer for creating spans around agent steps,
plugin calls, and webhook processing.

Traces hierarchy:
  process_pr
  ├── scanner_agent
  │   ├── semgrep.scan
  │   └── github.get_diff
  ├── intelligence_agent
  │   ├── risk.assess
  │   ├── patterns.query
  │   └── compliance.map
  └── remediation_agent
      ├── fix.generate
      ├── fix.validate
      ├── github.post_review
      └── compliance.evidence
"""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

logger = logging.getLogger("secureflow.telemetry")

_TRACER_NAME = "secureflow-ai"
_initialized = False


def init_telemetry(
    appinsights_connection_string: str = "",
    service_name: str = "secureflow-ai",
    service_version: str = "0.1.0",
) -> trace.Tracer:
    """Initialize OpenTelemetry with Azure Monitor exporter.

    If no connection string is provided, tracing is set up with
    a console exporter for local development.

    Returns the configured tracer instance.
    """
    global _initialized
    if _initialized:
        return trace.get_tracer(_TRACER_NAME)

    resource = Resource.create({
        "service.name": service_name,
        "service.version": service_version,
    })
    provider = TracerProvider(resource=resource)

    if appinsights_connection_string:
        try:
            from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter

            exporter = AzureMonitorTraceExporter(
                connection_string=appinsights_connection_string,
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("Azure Monitor trace exporter configured")
        except ImportError:
            logger.warning(
                "azure-monitor-opentelemetry-exporter not installed — "
                "traces will not be sent to Application Insights"
            )
        except Exception as e:
            logger.warning("Failed to configure Azure Monitor exporter: %s", e)
    else:
        # Local dev: optional console export
        try:
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter

            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            logger.info("Console trace exporter configured (no AppInsights connection string)")
        except Exception:
            pass

    trace.set_tracer_provider(provider)
    _initialized = True
    return trace.get_tracer(_TRACER_NAME)


def get_tracer() -> trace.Tracer:
    """Get the SecureFlow tracer (must call init_telemetry first)."""
    return trace.get_tracer(_TRACER_NAME)


def traced(
    span_name: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> Callable:
    """Decorator to wrap an async function in an OTel span.

    Usage:
        @traced("scanner.analyze")
        async def analyze_files(...):
            ...

        @traced(attributes={"agent": "intelligence"})
        async def prioritize(...):
            ...
    """
    def decorator(fn: Callable) -> Callable:
        name = span_name or f"{fn.__module__}.{fn.__qualname__}"

        @wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for key, val in attributes.items():
                        span.set_attribute(key, val)
                try:
                    result = await fn(*args, **kwargs)
                    span.set_status(trace.StatusCode.OK)
                    return result
                except Exception as e:
                    span.set_status(trace.StatusCode.ERROR, str(e))
                    span.record_exception(e)
                    raise

        return wrapper
    return decorator

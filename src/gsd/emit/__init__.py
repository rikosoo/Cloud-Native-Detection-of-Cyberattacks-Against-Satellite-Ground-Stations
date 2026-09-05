"""Sinks that carry simulated events and findings into AWS."""

from gsd.emit.sinks import FileSink, Sink, StdoutSink, build_sink

__all__ = ["FileSink", "Sink", "StdoutSink", "build_sink"]

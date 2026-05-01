# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Enterprise transport interceptors — Phase F-3/F-4."""
from __future__ import annotations

__all__ = ["PramanixGrpcInterceptor", "PramanixKafkaConsumer"]


def __getattr__(name: str) -> object:
    """Lazy import of interceptor classes (PEP 562).

    Defers loading of optional heavy dependencies (grpcio, confluent-kafka)
    until actually accessed, preventing eager import failures and test
    ordering interference.
    """
    if name == "PramanixGrpcInterceptor":
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor
        return PramanixGrpcInterceptor
    if name == "PramanixKafkaConsumer":
        from pramanix.interceptors.kafka import PramanixKafkaConsumer
        return PramanixKafkaConsumer
    raise AttributeError(f"module 'pramanix.interceptors' has no attribute {name!r}")

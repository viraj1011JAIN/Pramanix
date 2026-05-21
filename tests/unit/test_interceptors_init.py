# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
import pytest


def test_interceptors_init_imports():
    from pramanix.interceptors import PramanixGrpcInterceptor, PramanixKafkaConsumer

    assert PramanixGrpcInterceptor is not None
    assert PramanixKafkaConsumer is not None


def test_interceptors_init_attribute_error():
    import pramanix.interceptors

    with pytest.raises(AttributeError):
        _ = pramanix.interceptors.NonExistentInterceptor

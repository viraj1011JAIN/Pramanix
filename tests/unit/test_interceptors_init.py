import pytest

def test_interceptors_init_imports():
    from pramanix.interceptors import PramanixGrpcInterceptor, PramanixKafkaConsumer
    assert PramanixGrpcInterceptor is not None
    assert PramanixKafkaConsumer is not None

def test_interceptors_init_attribute_error():
    import pramanix.interceptors
    with pytest.raises(AttributeError):
        pramanix.interceptors.NonExistentInterceptor

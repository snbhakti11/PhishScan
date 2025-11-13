import pytest
from phishscan.extract_features import extract_features


def test_extract_features_basic_keys():
    url = 'http://example.com/login'
    feats = extract_features(url)
    # basic keys we expect
    expected_keys = ['url_length', 'num_dots', 'entropy']
    for k in expected_keys:
        assert k in feats
        assert isinstance(feats[k], (int, float))


def test_extract_features_values_reasonable():
    url = 'http://example.com/login123'
    feats = extract_features(url)
    assert feats['url_length'] > 0
    assert feats['num_dots'] >= 1
import pytest
from phishscan.extract_features import extract_features


def test_extract_features_basic():
    url = "http://example.com/login"
    feats = extract_features(url)
    # basic expectations
    assert isinstance(feats, dict)
    # important numeric keys
    for k in [
        'url_length', 'num_dots', 'num_digits', 'entropy',
        'ssl_expiry_days', 'domain_age_days',
        'form_count', 'script_count'
    ]:
        assert k in feats
        assert isinstance(feats[k], (int, float))

if __name__ == '__main__':
    pytest.main([__file__])

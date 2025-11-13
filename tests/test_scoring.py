import json
import os
import pytest

from phishscan import api


@pytest.fixture
def client():
    api.app.config['TESTING'] = True
    with api.app.test_client() as c:
        yield c


def test_threshold_get_set(client):
    # GET default
    rv = client.get('/config/threshold')
    assert rv.status_code == 200
    data = rv.get_json()
    assert 'threshold' in data

    # POST update
    rv = client.post('/config/threshold', json={'threshold': 0.42})
    assert rv.status_code == 200
    data = rv.get_json()
    assert abs(data['threshold'] - 0.42) < 1e-6


def test_scan_url_heuristics_score_and_verdict():
    # Basic test: scan_url should return heuristics with score 0..100 and a final_verdict
    from phishscan.app.scanner import scan_url
    r = scan_url('http://example.com')
    assert 'heuristics' in r
    heur = r['heuristics']
    assert isinstance(heur.get('score', 0), int)
    assert 0 <= heur['score'] <= 100
    assert 'final_verdict' in heur


def test_predict_combined_fields(client):
    # Ensure /predict returns combined_probability and final_verdict and features
    rv = client.post('/predict', json={'url': 'http://example.com'})
    assert rv.status_code == 200
    d = rv.get_json()
    assert 'combined_probability' in d
    assert 'final_verdict' in d
    assert 'features' in d

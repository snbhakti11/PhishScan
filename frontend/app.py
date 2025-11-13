from flask import Flask, render_template, request, jsonify
import os, requests

app = Flask(__name__, template_folder='templates', static_folder='static')

BACKEND_URL = os.getenv('BACKEND_URL', 'http://127.0.0.1:5050')


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/submit', methods=['POST'])
def submit():
    data = request.form or request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'missing url'}), 400

    # call backend predict first (ML only)
    try:
        r = requests.post(f'{BACKEND_URL}/predict', json={'url': url}, timeout=15)
        pred = r.json()
    except Exception as e:
        return jsonify({'error': f'backend predict failed: {e}'}), 502

    # Use /predict as canonical source for combined_probability and verdict
    mlp = None
    combined = None
    verdict = None

    if isinstance(pred, dict):
        mlp = (
            pred.get('ml_probability')
            or pred.get('phishing_probability')
            or pred.get('result', {}).get('ml_probability')
            or pred.get('result', {}).get('phishing_probability')
        )
        combined = pred.get('combined_probability') or pred.get('ml_probability') or mlp
        verdict = pred.get('final_verdict') or pred.get('result', {}).get('final_verdict')

    # extract severity from predict's heuristics if present
    severity = None
    if isinstance(pred, dict):
        severity = pred.get('result', {}).get('heuristics', {}).get('severity') or pred.get('heuristics', {}).get('severity')

    resp = {
        'url': url,
        'ml_probability': mlp,
        'combined_probability': combined,
        'final_verdict': verdict,
        'severity': severity,
        'raw_predict': pred,
    }
    return jsonify(resp)


if __name__ == '__main__':
    port = int(os.getenv('PORT', '8080'))
    app.run(host='0.0.0.0', port=port)

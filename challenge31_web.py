from flask import Flask, redirect, url_for, request, abort
import secrets

import challenge1
import challenge29
import challenge31

app = Flask(__name__)
key = secrets.token_bytes(20)

@app.route('/read')
def read():
    filename = request.args.get('file')
    signature = request.args.get('signature')
    if filename and signature:
        required_sign = challenge31.hmac(challenge29.sha1, filename, key)
        required_sign = challenge1.encode_hexstr(required_sign)
        if challenge31.insecure_compare(signature, required_sign):
            with open(filename) as f:
                content = f.read()
            return content
        else:
            abort(500)

    return redirect(url_for('index'))

@app.route('/')
def index():
    filename = b'challenge31.py'
    signature = challenge31.hmac(challenge29.sha1, filename, key)
    signature = challenge1.encode_hexstr(signature)
    return redirect(url_for('read', file=filename, signature=signature))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1234)


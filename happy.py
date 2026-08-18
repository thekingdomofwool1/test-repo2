"""
Python Security Test Suite
Targets: eval() code execution and non-cryptographic PRNG usage.
"""

from flask import Flask, request, jsonify
import random

app = Flask(__name__)

# =========================================================================
# RULE 3: Unsafe Evaluation of User Input with eval() in Python
# Pattern: Passing request parameters directly into eval()
# =========================================================================
@app.route("/api/calculate", methods=["POST", "GET"])
def dynamic_eval_handler():
    # Taint Source: User-controlled expression from query or POST body
    user_formula = request.args.get("formula") or request.json.get("expression")

    # Taint Sink: Direct eval() of unsanitized user input (CWE-95)
    evaluated_result = eval(user_formula)

    return jsonify({"result": evaluated_result})


# =========================================================================
# Insecure Random Number Generation in Python
# Pattern: random.random / random.choice used for authentication tokens
# =========================================================================
@app.route("/api/auth/reset-password", methods=["POST"])
def create_reset_token():
    # Taint / Vuln: standard `random` uses Mersenne Twister (predictable after 624 outputs)
    # Should use `secrets.token_hex()`
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = "".join(random.choice(charset) for _ in range(32))
    otp_code = random.randint(100000, 999999)

    return jsonify({"reset_token": token, "otp": otp_code})


if __name__ == "__main__":
    app.run(port=5000)

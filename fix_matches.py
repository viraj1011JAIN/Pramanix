import re

filepath = r"c:\Pramanix\tests\unit\test_mesh_authenticator.py"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Map of old match strings -> new match strings
replacements = [
    # authenticate_and_bind
    ('match="intent_poisoning"', 'match="Intent poisoning"'),
    # verify_svid / general token checks
    ('match="missing_token"', 'match="missing or empty"'),
    ('match="token_too_large"', 'match="exceeds the maximum"'),
    ('match="malformed_token"', 'match="dot-separated"'),
    ('match="disallowed_algorithm"', 'match="uses algorithm"'),
    ('match="invalid_signature"', 'match="verification failed"'),
    ('match="missing_exp"', 'match="required .exp.'),
    ('match="missing_aud"', "match=\"required 'aud'\""),
    ('match="audience_mismatch"', 'match="does not contain"'),
    ('match="missing_sub"', "match=\"'sub' claim\""),
    ('match="bad_spiffe_uri"', 'match="valid SPIFFE"'),
    # decode_jwt_parts
    ('match="malformed_header"', 'match="header"'),
    ('match="malformed_payload"', 'match="payload"'),
    # temporal claims
    ('match="malformed_exp"', 'match="not a valid integer"'),
    ('match="not_yet_valid"', 'match="not yet valid"'),
    ('match="malformed_nbf"', 'match="not a valid integer"'),
    # fetch_jwks
    ('match="jwks_timeout"', 'match="timed out"'),
    ('match="jwks_http_error"', 'match="returned HTTP"'),
    ('match="jwks_unreachable"', 'match="unreachable"'),
    ('match="jwks_invalid_json"', 'match="not valid JSON"'),
    ('match="jwks_missing_keys"', 'match="missing"'),
    ('match="jwks_empty"', 'match="no keys"'),
    # select_jwk
    ('match="unknown_kid"', 'match="No JWK with kid"'),
    # jwk_to_public_key
    ('match="malformed_jwk"', 'match="missing required parameter"'),
    ('match="unsupported_curve"', "match=\"Only 'P-256'\""),
    ('match="unsupported_kty"', 'match="Unsupported JWK key type"'),
]

# Apply replacements sequentially
for old, new in replacements:
    content = content.replace(old, new)

# Special fix: missing_exp used raw quote style - fix the required 'exp' match
content = content.replace("match=\"required .exp.", "match=\"required 'exp'\"")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Done. Verifying no old patterns remain...")
# Check none of the old patterns remain
old_patterns = ["intent_poisoning", "missing_token", "token_too_large", "malformed_token",
                "disallowed_algorithm", "invalid_signature", "missing_exp", "missing_aud",
                "audience_mismatch", "missing_sub", "bad_spiffe_uri", "malformed_header",
                "malformed_payload", "malformed_exp", "not_yet_valid", "malformed_nbf",
                "jwks_timeout", "jwks_http_error", "jwks_unreachable", "jwks_invalid_json",
                "jwks_missing_keys", "jwks_empty", "unknown_kid", "malformed_jwk",
                "unsupported_curve", "unsupported_kty"]

remaining = []
for pattern in old_patterns:
    if f'match="{pattern}"' in content:
        remaining.append(pattern)

if remaining:
    print(f"WARNING: These old patterns still remain as match= values: {remaining}")
else:
    print("All old reason-code match patterns have been fixed.")

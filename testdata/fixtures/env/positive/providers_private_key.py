# seeded defects: PEM private-key block shapes (bodies are fake/truncated)
# covers private-key-block (3) — CLAUDE.md hard rule 3 fixture backfill.

rsa_key = """-----BEGIN RSA PRIVATE KEY-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
-----END RSA PRIVATE KEY-----"""

ec_key = """-----BEGIN EC PRIVATE KEY-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
-----END EC PRIVATE KEY-----"""

ssh_key = """-----BEGIN OPENSSH PRIVATE KEY-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
-----END OPENSSH PRIVATE KEY-----"""

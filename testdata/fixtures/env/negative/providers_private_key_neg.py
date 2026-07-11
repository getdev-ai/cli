# must NOT fire: PEM blocks that are NOT private keys, and prose that merely
# mentions private keys without an actual PEM block.
cert = """-----BEGIN CERTIFICATE-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
-----END CERTIFICATE-----"""

pub_key = """-----BEGIN PUBLIC KEY-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
-----END PUBLIC KEY-----"""

note = "remember to rotate the private key before shipping"

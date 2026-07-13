# positive: a credentialed Postgres DSN — the embedded password must be
# extracted to `.env` and its masked preview must never print the credential.
database_url = "postgres://appuser:s3cr3tPw0rd@db.internal:5432/app"


def connect():
    return database_url

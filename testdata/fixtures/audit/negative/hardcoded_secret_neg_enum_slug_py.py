# PREC-04: an enum/const whose value is a lowercase snake_case slug — a
# permission taxonomy constant, not a random secret body. The identifier looks
# secret-ish ("AUTHORITY" contains "auth"), but the VALUE is an identifier slug.
REVOKE_STAFF_AUTHORITY = "revoke_staff_authority"
GRANT_STAFF_AUTHORITY = "grant_staff_authority"


def authority_slug() -> str:
    return REVOKE_STAFF_AUTHORITY

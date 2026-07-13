# negative: a URL that appears only inside a comment is not a real string
# assignment — the assignment walk never yields it, so it must stay silent.
# local dev connects to postgres://dev:dev@localhost:5432/dev (do not commit)
service_name = "orders-api"


def name():
    return service_name

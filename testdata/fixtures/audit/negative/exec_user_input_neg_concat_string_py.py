# Plain string concatenation with no shell-invoking call — must NOT trip.
def greet(name):
    message = "hello " + name
    return message

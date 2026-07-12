# W3: eval() applied to an attribute access (req.body) — the Python
# attribute matcher that previously had no positive fixture.
def run_expression(req):
    return eval(req.body)

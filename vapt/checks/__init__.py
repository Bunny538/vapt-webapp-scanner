from . import authbypass, cookies, cors, disclosure, forms, headers, methods, paths, redirect, sqli, tls, traversal, xss

ALL = {m.NAME: m for m in (headers, cookies, cors, methods, disclosure, paths, forms, tls, redirect, xss, sqli, traversal, authbypass)}

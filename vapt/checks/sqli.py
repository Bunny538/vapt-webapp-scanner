"""SQL injection detection: error-based and boolean-based. Read-only, no data extraction."""
import re

from ..models import Finding

NAME = "sqli"
ERRORS = re.compile("|".join([
    r"sqlite3\.(Operational|Programming)Error", r"unrecognized token", r"SQLITE_ERROR",
    r"You have an error in your SQL syntax", r"mysql_fetch", r"MySqlException",
    r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"syntax error at or near", r"unterminated quoted string",
    r"SQLSTATE\[", r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
    r"near \"[^\"]{0,40}\": syntax error",
]), re.I)
OWASP = "A03:2021 Injection"
FIX = ("Use parameterised queries / prepared statements (never string concatenation), apply least-privilege "
       "database accounts, and return generic error messages.")


def run(ctx):
    out = []
    for pt in ctx.testable_points():
        orig = pt.params.get(pt.name, "")
        base = ctx.send(pt, orig)
        if base is None:
            continue
        err = ctx.send(pt, orig + "'")
        if err is not None:
            m = ERRORS.search(err.text)
            if m and not ERRORS.search(base.text):
                out.append(Finding(
                    "VAPT-SQLI-001", "SQL injection (error-based)", "high", pt.url,
                    "A single quote in the parameter triggered a database error, indicating user input is "
                    "concatenated into a SQL query.",
                    FIX, evidence=f"{pt.name}={orig!r}' -> HTTP {err.status_code}: {m.group(0)}",
                    parameter=pt.name, cwe="CWE-89", owasp=OWASP))
                continue
        # Boolean-based: TRUE condition == baseline, FALSE condition differs. Needs a stable baseline.
        base2 = ctx.send(pt, orig)
        if base2 is None or base2.text != base.text:
            continue
        t = ctx.send(pt, orig + "' AND '1'='1")
        f = ctx.send(pt, orig + "' AND '1'='2")
        if t is not None and f is not None and t.text == base.text and f.text != base.text:
            out.append(Finding(
                "VAPT-SQLI-002", "SQL injection (boolean-based, likely)", "medium", pt.url,
                "Logically true and false injected conditions produce different responses, "
                "suggesting the input reaches a SQL query.",
                FIX, evidence=f"{pt.name}: TRUE condition matched baseline, FALSE condition differed",
                parameter=pt.name, cwe="CWE-89", owasp=OWASP))
    return out

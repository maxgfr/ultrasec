import csv
import io


def cell(value):
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def users_csv(users):
    out = io.StringIO()
    writer = csv.writer(out)
    for u in users:
        writer.writerow([cell(u.name), cell(u.email)])
    return out.getvalue()

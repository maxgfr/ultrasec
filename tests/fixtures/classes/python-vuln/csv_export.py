import csv
import io


def users_csv(users):
    out = io.StringIO()
    writer = csv.writer(out)
    for u in users:
        writer.writerow([u.name, u.email])
    return out.getvalue()

import csv


def export(rows, out):
    writer = csv.writer(out)
    # A cell starting with = + - @ executes when the file opens in a spreadsheet.
    return writer.writerows(rows)

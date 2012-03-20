

def report_header(text=None, token='-'):
    report = []
    border = token*len(text)
    report.append(border)
    report.append(text)
    report.append(border)
    return report
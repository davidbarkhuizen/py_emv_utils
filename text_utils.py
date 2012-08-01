def write_header(s, logging_fn, header_char='-'):
    logging_fn(header_char*len(s))
    logging_fn(s)
    logging_fn(header_char*len(s))

def write_header_with_trailing_line(s, logging_fn, header_char='-'):
    write_header(s, logging_fn, header_char)
    logging_fn('')

def report_header(text=None, token='-'):
    report = []
    border = token*len(text)
    report.append(border)
    report.append(text)
    report.append(border)
    return report
import logging
from datetime import datetime

def init_logging(file_name='log',file_extension='log',file_path='',stamp_with_time=True,log_format="%(message)s",verbose=True,log_to_console=True):
    
    # GEN TIME STAMP STRING
    t = datetime.now()
    tstamp = '%d-%d-%d-%d-%d' % (t.year, t.month, t.day, t.hour, t.minute)
    
    # GEN FILE NAME w PATH
    fname = ''
    if (stamp_with_time == True):  
        fname = file_path + file_name + '_' + tstamp + '.' + file_extension
    else:
        fname = file_path + file_name + '.' + file_extension
    
    # CONFIG/INIT LOGGING
    logging.basicConfig(filename=fname, level=logging.INFO, format=log_format)
    
    # PRINT IF VERBOSE
    if (verbose):
        print('logging to file %s' % fname)            

    if (log_to_console == True):  
    
        class LogToConsoleHandler(logging.Handler):
            def emit(self, record):
                print(record.msg)
    
        logging.getLogger().addHandler(LogToConsoleHandler())  

if __name__ == '__main__':
    pass
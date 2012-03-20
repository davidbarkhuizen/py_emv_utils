class SELECT(object):
    cla = 0x00
    ins = 0xA4

# ------------------------------------------------------------------------------

class READ_RECORD(object):
    cla = 0x00
    ins = 0xB2

# ------------------------------------------------------------------------------

class GET_PROCESSING_OPTIONS(object):
    cla = 0x80
    ins = 0xA8

# ------------------------------------------------------------------------------

class GET_DATA(object):
    cla = 0x80
    ins = 0xCA

# ------------------------------------------------------------------------------

class GET_CHALLENGE(object):
    cla = 0x00
    ins = 0x84
    p1 = 0x00
    p2 = 0x00
    le = 0x00
    
# ------------------------------------------------------------------------------
    
class VERIFY(object):
    cla = 0x00
    ins = 0x20
    p1 = 0x00

# --------------------------------------------------------------------------------------------------
    
def select(connection=None, cla=None, ins=None, p1=None, p2=None, lc=None, data=None, le=None):

    apdu = [cla, ins, p1, p2]    
        
    # LC
    if lc:
        apdu.append(lc)
    else:
        if data:
            # LC
            lc = len(data)
            apdu.append(lc)            
            # DATA
            for data_byte in data:
                apdu.append(data_byte)
    # LE
    if le:
        apdu.append(le)
    
    reply_data, sw1, sw2 = connection.transmit(apdu)
    return (reply_data, sw1, sw2)

def select_and_requery(connection=None, cla=None, ins=None, p1=None, p2=None, lc=None, data=None, le=None):
    
    initial_reply_data, initial_sw1, initial_sw2 = select(connection=connection, cla=cla, ins=ins, p1=p1, p2=p2, lc=lc, data=data, le=le)
    
    # SW1 = 0x61 => retrieve data using GET RESPONSE command
    if (initial_sw1 == 0x61):
        return select(connection=connection, cla=0x00, ins=0xC0, p1=0x00, p2=0x00, le=initial_sw2)
    # SW1 = 0x6c => retrieve data by repeating initial command
    elif (initial_sw1 == 0x6c):
        return select(connection=connection, cla=cla, ins=ins, p1=p1, p2=p2, lc=lc, data=data, le=initial_sw2)
    # initial response indicates other error
    else:
        return (initial_reply_data, initial_sw1, initial_sw2)

def report_on_reply(sw1, sw2, data, log_data_content=True):
    
    lines = []
    
    lines.append('SW1:SW2 = %s-%s, %s-%s, len(data) = %i' % (str(sw1), str(sw2), hex(sw1), hex(sw2), len(data)))
    
    if (log_data_content):    
        if data:        
            lines.append('HEX   ' + '.'.join(['%02X' % x for x in data]))
            lines.append('BIN   ' + '.'.join(['%i' % x for x in data]))
        else:
            lines.append('NO DATA')
    
    return lines
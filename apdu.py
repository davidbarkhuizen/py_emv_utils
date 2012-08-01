class StatusWordSimple(object):
    def __init__(self, sw1, sw2, msg):
        self.sw1 = sw1
        self.sw2 = sw2
        self.msg = msg
    def matches(self, other_sw1, other_sw2):
        return (self.sw1 == other_sw1) and (self.sw2 == other_sw2)
    def gen_msg(self):
        return self.msg
        
class StatusWordComplex(object):
    def __init__(self, sw1, sw2_matcher, msg_generator):
        self.sw1 = sw1
        self.sw2_matcher = sw2_matcher
        self.msg_generator = msg_generator
    def matches(self, other_sw1, other_sw2):
        return (self.sw1 == other_sw1) and (self.sw2_matcher(other_sw2) == True)
    def gen_msg(self):
        return self.msg_generator(other_sw2)
        
normal_statuses = [
    StatusWordSimple('90', '00', 'Process completed (any other value for SW2 is RFU)'),
    ]

warning_statuses = [
    StatusWordSimple('62', '83', 'State of non-volatile memory unchanged; selected file invalidated'),
    StatusWordSimple('63', '00', 'State of non-volatile memory changed; authentication failed'),
    StatusWordComplex('63', lambda Cx : Cx[0] == 'C', lambda Cx : 'State of non-volatile memory changed; counter provided by %s (from 0-15)' % Cx[1])
    ]

error_statuses = [
    StatusWordSimple('69', '83', 'Command not allowed; authentication method blocked'),
    StatusWordSimple('69', '84', 'Command not allowed; referenced data invalidated'),
    StatusWordSimple('69', '85', 'Command not allowed; conditions of use not satisfied'),
    StatusWordSimple('6A', '81', 'Wrong parameter(s) P1 P2; function not supported'),
    StatusWordSimple('6A', '82', 'Wrong parameter(s) P1 P2; file not found'),
    StatusWordSimple('6A', '83', 'Wrong parameter(s) P1 P2; record not found'),
    StatusWordSimple('6A', '88', 'Referenced data (data objects) not found'),
    ]

statuses = { 'normal' : normal_statuses, 
    'warning' : warning_statuses,
    'error' : error_statuses
    }

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

def report_on_reply(sw1, sw2, data, log_data_content=False):
    
    lines = []

    sw1_str = '%02X' % sw1
    sw2_str = '%02X' % sw2
    
    msg = None
    
    for status_type in statuses:
        for status in statuses[status_type]:
            if status.matches(sw1_str, sw2_str):
                msg = status_type + ' - ' + status.gen_msg()

    lines.append('STATUS:  %s. SW1:SW2 = %s-%s, len(data) = %i' % (msg, sw1_str, sw2_str, len(data)))
    
    if (log_data_content):    
        if data:        
            lines.append('HEX   ' + '.'.join(['%02X' % x for x in data]))
        else:
            lines.append('NO DATA')
    
    return lines
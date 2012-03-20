from bit_tools import BitFlag
import bit_tools



class AIP(object):

    bit_flags = []

    # Byte 1
    bit_flags.append(BitFlag(1, 1, 'CDA supported'))
    bit_flags.append(BitFlag(1, 2, 'RFU'))
    bit_flags.append(BitFlag(1, 3, 'Issuer authentication is supported'))
    bit_flags.append(BitFlag(1, 4, 'Terminal risk management is to be performed'))
    bit_flags.append(BitFlag(1, 5, 'Cardholder verification is supported'))
    bit_flags.append(BitFlag(1, 6, 'DDA supported'))
    bit_flags.append(BitFlag(1, 7, 'SDA supported'))
    bit_flags.append(BitFlag(1, 8, 'RFU'))
    # Byte 2
    bit_flags.append(BitFlag(2, 1, 'RFU'))
    bit_flags.append(BitFlag(2, 2, 'RFU'))
    bit_flags.append(BitFlag(2, 3, 'RFU'))
    bit_flags.append(BitFlag(2, 4, 'RFU'))
    bit_flags.append(BitFlag(2, 5, 'RFU'))
    bit_flags.append(BitFlag(2, 6, 'RFU'))
    bit_flags.append(BitFlag(2, 7, 'RFU'))
    bit_flags.append(BitFlag(2, 8, 'RFU'))
    
    def __init__(self, byte_list):
        self.byte_list = byte_list        
        
    def report(self):
        
        report = []
        
        for bit_flag in self.bit_flags:
            if bit_tools.bit_flag_is_set_in_byte_list(self.byte_list, bit_flag):
                report.append(bit_flag.description)
                
        return report
    
    def __str__(self):
        return '.'.join(['%02X' % x for x in self.byte_list])
        
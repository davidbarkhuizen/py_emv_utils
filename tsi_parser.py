import logging
from log_util import init_logging

import binascii

from bit_tools import BitFlag
from bit_tools import CompositeBitFlag
from bit_tools import Nibble

from bit_tools import bit_flag_is_set_in_byte_list 
from bit_tools import hex_string_to_byte_list
from text_utils import report_header

def construct_tsi_bit_flags():
    '''
    # EMV 4.2 Book 3 = Application Specification
    # Annex C = Coding Data Elements Used in Trans Processing
    # C6 = Transaction Status Information
    # 1 => LSB, 8 => MSB
    '''

    bit_flag_list = []
    # Byte 1
    bit_flag_list.append(BitFlag(1, 8, 'Offline data authentication was performed'))
    bit_flag_list.append(BitFlag(1, 7, 'Cardholder verification was performed'))
    bit_flag_list.append(BitFlag(1, 6, 'Card risk management was performed'))
    bit_flag_list.append(BitFlag(1, 5, 'Issuer authentication was performed'))
    bit_flag_list.append(BitFlag(1, 4, 'Terminal risk management was performed'))
    bit_flag_list.append(BitFlag(1, 3, 'Script processing was performed'))
    bit_flag_list.append(BitFlag(1, 2, 'RFU'))
    bit_flag_list.append(BitFlag(1, 1, 'RFU'))
    # Byte 2
    bit_flag_list.append(BitFlag(2, 8, 'RFU'))
    bit_flag_list.append(BitFlag(2, 7, 'RFU'))
    bit_flag_list.append(BitFlag(2, 6, 'RFU'))
    bit_flag_list.append(BitFlag(2, 5, 'RFU'))
    bit_flag_list.append(BitFlag(2, 4, 'RFU'))
    bit_flag_list.append(BitFlag(2, 3, 'RFU'))
    bit_flag_list.append(BitFlag(2, 2, 'RFU'))
    bit_flag_list.append(BitFlag(2, 1, 'RFU'))
    
    return bit_flag_list

def parse_tsi(tsi_hex_string):    
    
    report = []
    for l in report_header('TSI : Transaction Status Information', '='): report.append(l)

    report.append('raw hex %s' % tsi_hex_string)
    tsi_byte_list = hex_string_to_byte_list(tsi_hex_string)
    report.append('    hex %s' % '.'.join(['%02X' % x for x in tsi_byte_list]))
    report.append('    dec %s' % '.'.join(['%i' % x for x in tsi_byte_list]))

    for l in report_header('Bit Flags', '-'): report.append(l)
    tsi_flags = construct_tsi_bit_flags()
    for flag in tsi_flags:
        if (bit_flag_is_set_in_byte_list(tsi_byte_list, flag) == True):
            report.append(flag.description)

    for line in report:
        logging.info(line)

if __name__ == '__main__':
    init_logging(file_name='/logs/tsi_parser')
    sample_tsi = 'E800'
    parse_tsi(sample_tsi)



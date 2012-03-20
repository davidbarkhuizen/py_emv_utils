import logging
from log_util import init_logging

import binascii

from bit_tools import BitFlag
from bit_tools import bit_flag_is_set_in_byte_list 
from bit_tools import hex_string_to_byte_list

from text_utils import report_header

def construct_tvr_bit_flags():
    '''
    # EMV 4.2 Book 3 = Application Specification
    # Annex C = Coding Data Elements Used in Trans Processing
    # C5 = Terminal Verification Results
    # 1 => LSB, 8 => MSB
    '''

    bit_flag_list = []
    # Byte 1
    bit_flag_list.append(BitFlag(1, 8, 'Offline data authentication was not performed'))
    bit_flag_list.append(BitFlag(1, 7, 'SDA failed'))
    bit_flag_list.append(BitFlag(1, 6, 'ICC data missing'))
    bit_flag_list.append(BitFlag(1, 5, 'Card appears on terminal exception file'))
    bit_flag_list.append(BitFlag(1, 4, 'DDA failed'))
    bit_flag_list.append(BitFlag(1, 3, 'CDA failed'))
    bit_flag_list.append(BitFlag(1, 2, 'RFU'))
    bit_flag_list.append(BitFlag(1, 1, 'RFU'))
    # Byte 2
    bit_flag_list.append(BitFlag(2, 8, 'ICC and terminal have different application versions'))
    bit_flag_list.append(BitFlag(2, 7, 'Expired application'))
    bit_flag_list.append(BitFlag(2, 6, 'Application not yet effective'))
    bit_flag_list.append(BitFlag(2, 5, 'Requested service not allowed for card product'))
    bit_flag_list.append(BitFlag(2, 4, 'New card'))
    bit_flag_list.append(BitFlag(2, 3, 'RFU'))
    bit_flag_list.append(BitFlag(2, 2, 'RFU'))
    bit_flag_list.append(BitFlag(2, 1, 'RFU'))
    # Byte 3
    bit_flag_list.append(BitFlag(3, 8, 'Cardholder verification was not successful'))
    bit_flag_list.append(BitFlag(3, 7, 'Unrecognised CVM'))
    bit_flag_list.append(BitFlag(3, 6, 'PIN Try Limit exceeded'))
    bit_flag_list.append(BitFlag(3, 5, 'PIN entry required and PIN pad not present or not working'))
    bit_flag_list.append(BitFlag(3, 4, 'PIN entry required, PIN pad present, but PIN was not entered'))
    bit_flag_list.append(BitFlag(3, 3, 'Online PIN entered'))
    bit_flag_list.append(BitFlag(3, 2, 'RFU'))
    bit_flag_list.append(BitFlag(3, 1, 'RFU'))
    # Byte 4
    bit_flag_list.append(BitFlag(4, 8, 'Transaction exceeds floor limit'))
    bit_flag_list.append(BitFlag(4, 7, 'Lower consecutive offline limit exceeded'))
    bit_flag_list.append(BitFlag(4, 6, 'Upper consecutive offline limit exceeded'))
    bit_flag_list.append(BitFlag(4, 5, 'Transaction selected randomly for online processing'))
    bit_flag_list.append(BitFlag(4, 4, 'Merchant forced transaction online'))
    bit_flag_list.append(BitFlag(4, 3, 'RFU'))
    bit_flag_list.append(BitFlag(4, 2, 'RFU'))
    bit_flag_list.append(BitFlag(4, 1, 'RFU'))
    # Byte 5
    bit_flag_list.append(BitFlag(5, 8, 'Default TDOL used'))
    bit_flag_list.append(BitFlag(5, 7, 'Issuer authentication failed'))
    bit_flag_list.append(BitFlag(5, 6, 'Script processing failed before final GENERATE AC'))
    bit_flag_list.append(BitFlag(5, 5, 'Script processing failed after final GENERATE AC'))
    bit_flag_list.append(BitFlag(5, 4, 'RFU'))
    bit_flag_list.append(BitFlag(5, 3, 'RFU'))
    bit_flag_list.append(BitFlag(5, 2, 'RFU'))
    bit_flag_list.append(BitFlag(5, 1, 'RFU'))
    
    return bit_flag_list

def parse_tvr(tvr_hex_string):    
    
    report = []
    for l in report_header('TVR : Terminal Verification Results', '='): report.append(l)
    
    report.append('raw hex %s' % tvr_hex_string)
    tvr_byte_list = hex_string_to_byte_list(tvr_hex_string)
    report.append('    hex %s' % '.'.join(['%02X' % x for x in tvr_byte_list]))
    report.append('    dec %s' % '.'.join(['%i' % x for x in tvr_byte_list]))
    
    for l in report_header('Bit Flags', '-'): report.append(l)
    tvr_flags = construct_tvr_bit_flags()
    for flag in tvr_flags:
        if (bit_flag_is_set_in_byte_list(tvr_byte_list, flag) == True):
            report.append(flag.description)

    for line in report:
        logging.info(line)


if __name__ == '__main__':
    init_logging(file_name='/logs/tvr_parser')
    # sample_tvr = '8000048000'
    sample_tvr = '0000008000'
    parse_tvr(sample_tvr)


'''
# Byte 2
bit_flag_list.append(BitFlag(1, 1, ''))
bit_flag_list.append(BitFlag(1, 2, ''))
bit_flag_list.append(BitFlag(1, 3, ''))
bit_flag_list.append(BitFlag(1, 4, ''))
bit_flag_list.append(BitFlag(1, 5, ''))
bit_flag_list.append(BitFlag(1, 6, ''))
bit_flag_list.append(BitFlag(1, 7, ''))
bit_flag_list.append(BitFlag(1, 8, ''))
'''
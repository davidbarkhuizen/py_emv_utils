import logging
from log_util import init_logging

import binascii

from bit_tools import BitFlag
from bit_tools import CompositeBitFlag
from bit_tools import Nibble

from bit_tools import bit_flag_is_set_in_byte_list 
from bit_tools import hex_string_to_byte_list
from text_utils import report_header

def construct_cvr_bit_flags():
    '''
    # EMV 4.2 Book 3 = Application Specification
    # Annex C = Coding Data Elements Used in Trans Processing
    # C7.3 = Card Verification Results
    # 1 => LSB, 8 => MSB
    '''

    bit_flag_list = []
    # Byte 1
    bit_flag_list.append(BitFlag(1, 4, 'CDA Performed'))
    bit_flag_list.append(BitFlag(1, 3, 'Offline DDA Performed'))
    bit_flag_list.append(BitFlag(1, 2, 'Issuer Authentication Not Performed'))
    bit_flag_list.append(BitFlag(1, 1, 'Issuer Authentication Failed'))
    # Byte 2
    bit_flag_list.append(BitFlag(2, 4, 'Offline PIN Verification Performed'))
    bit_flag_list.append(BitFlag(2, 3, 'Offline PIN Verification Performed and PIN Not Successfully Verified'))
    bit_flag_list.append(BitFlag(2, 2, 'PIN Try Limit Exceeded'))
    bit_flag_list.append(BitFlag(2, 1, 'Last Online Transaction Not Completed'))
    # Byte 3
    bit_flag_list.append(BitFlag(3, 8, 'Lower Offline Transaction Count Limit Exceeded'))
    bit_flag_list.append(BitFlag(3, 7, 'Upper Offline Transaction Count Limit Exceeded'))
    bit_flag_list.append(BitFlag(3, 6, 'Lower Cumulative Offline Amount Limit Exceeded'))
    bit_flag_list.append(BitFlag(3, 5, 'Upper Cumulative Offline Amount Limit Exceeded'))
    bit_flag_list.append(BitFlag(3, 4, 'Issuer-discretionary bit 1'))
    bit_flag_list.append(BitFlag(3, 3, 'Issuer-discretionary bit 2'))
    bit_flag_list.append(BitFlag(3, 2, 'Issuer-discretionary bit 3'))
    bit_flag_list.append(BitFlag(3, 1, 'Issuer-discretionary bit 4'))
    # Byte 4
    bit_flag_list.append(BitFlag(4, 4, 'Issuer Script Processing Failed'))
    bit_flag_list.append(BitFlag(4, 3, 'Offline Data Authentication Failed on Previous Transaction'))
    bit_flag_list.append(BitFlag(4, 2, 'Go Online on Next Transaction Was Set'))
    bit_flag_list.append(BitFlag(4, 1, 'Unable to go Online'))
    
    return bit_flag_list

def construct_cvr_composite_bit_flags():
    
    composite_flags = []
    
    # AC Types Returned in 1st Gen AC Cmd
    composite_flags.append(
        CompositeBitFlag(1, 
            [6,5], 
            'AC Type Returned in 1st GENERATE AC',
            {
            0 : 'AAC', 
            16 : 'TC', 
            32 : 'ARQC', 
            48 : 'RFU'
            })
        )
    
    # AC Type Returned in 2nd Gen AC Cmd
    composite_flags.append(
        CompositeBitFlag(1, 
            [8,7], 
            'AC Type Returned in 2nd GENERATE AC',
            {
            0 : 'AAC', 
            64 : 'TC', 
            128 : 'Second GENERATE AC Not Requested', 
            192 : 'RFU'
            })
        )
    
    return composite_flags

def construct_cvr_nibbles():
    '''
    # EMV 4.2 Book 3 = Application Specification
    # Annex C = Coding Data Elements Used in Trans Processing
    # C7.3 = Card Verification Results
    # 1 => LSB, 8 => MSB
    '''

    nibbles_list = []
    nibbles_list.append(Nibble(2, False,'Low Order Nibble of PIN Try Counter'))
    nibbles_list.append(Nibble(4, False, 'Number of Successfully Processed Issuer Script Commands Containing Secure Messaging'))
    return nibbles_list

def parse_cvr(cvr_hex_string):    
    
    report = []
    for l in report_header('CVR : Card Verification Results', '='): report.append(l)

    report.append('raw hex %s' % cvr_hex_string)
    cvr_byte_list = hex_string_to_byte_list(cvr_hex_string)
    report.append('    hex %s' % '.'.join(['%02X' % x for x in cvr_byte_list]))
    report.append('    dec %s' % '.'.join(['%i' % x for x in cvr_byte_list]))

    for l in report_header('Bit Flags', '-'): report.append(l)
    cvr_flags = construct_cvr_bit_flags()
    for flag in cvr_flags:
        if (bit_flag_is_set_in_byte_list(cvr_byte_list, flag) == True):
            report.append(flag.description)

    for l in report_header('Composite Bit Flags', '-'): report.append(l)
    cvr_sub_bytes = construct_cvr_composite_bit_flags()
    for sub_byte in cvr_sub_bytes:
        for line in sub_byte.evaluate_on_byte_list_and_report(cvr_byte_list):
            report.append(line)

    for l in report_header('Nibbles', '-'): report.append(l)
    cvr_nibbles = construct_cvr_nibbles()
    for nibble in cvr_nibbles:
        for line in nibble.evaluate_on_byte_list_and_report(cvr_byte_list):
            report.append(line)

    for line in report:
        logging.info(line)

if __name__ == '__main__':
    init_logging(file_name='/logs/cvr_parser')
    sample_cvr = '60100322'
    parse_cvr(sample_cvr)


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
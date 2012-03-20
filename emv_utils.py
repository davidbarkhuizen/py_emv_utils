# logging
import logging
import log_util

from binascii import hexlify, unhexlify

# pyscard
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.ATR import ATR
from smartcard.Exceptions import NoCardException
from smartcard.Exceptions import CardConnectionException

# custom
import tlv_utils
import tag_meanings
import aid_dict
from apdu import *
import chip_utils
from application_file_locator import ApplicationFileLocator
from application_interchange_profile import AIP

DO_LOG = False
COL_WIDTH = 30

PSE_DDF_NAME='1PAY.SYS.DDF01'
     
def get_pse_sfi(connection):
    '''
    attempt to retrieve SFI (Short File Identifier) 
    of the Directory Elementary File 
    of PSE (Payment System Environment)
    
    SUCCESS
    returns (sfi, tlv_tree)
    FAILURE
    returns (None, error_message)
    
    refer
    STRUCTURE OF THE PSE = 12.2.2
    APPLICATION SELECTION = EMV 4.2 Book 1 12 - page 135 / 151
    '''

    report = []

    # 3rd LSB bit-flag set => select by name    
    ref_control_param = 0x04
    
    # 00 => first-or-only-occurrence
    # 02 => next occurrence
    select_options = 0x00    
    
    data = [ord(c) for c in PSE_DDF_NAME]
    
    ret_data, sw1, sw2 = select_and_requery(connection=connection, 
        cla=SELECT.cla, ins=SELECT.ins,
        p1=ref_control_param, 
        p2=select_options, 
        data=data, 
        le=0x00)
    
    select_pse_error_tags = {
        '6A81' : 'card blocked, or select command not supported',
        '6A82' : 'no PSE / file not found',
        '6283' : 'PSE is blocked',
        }
    
    report.append('SELECT DIRECTORY DEFINITION FILE = 1PAY.SYS.DDF01')
    for x in report_on_reply(sw1, sw2, ret_data):
        report.append(x)
    
    hex = '%00X%00X' % (sw1, sw2)
    if hex not in select_pse_error_tags:
        
        # EMV 4.2 Book 1  - 11.3 Select Command-Response APDUs, Table 44
        # FCI Template returned by successful selection of a DDF
        # Response = 6f 19 84 0e 31 50 41 59 2e 53 59 53 2e 44 44 46 30 31 a5 07 88 01 01 9f 11 01 01
        
        # FCI Template
        # 6f 19 840e315041592e5359532e4444463031a5078801019f110101 (length = 50)
            # DF Name
            # 84 0e 315041592e5359532e4444463031
            # FCI Proprietary Template 
            # a5 07 8801019f110101
                # SFI of the Directory Elementary File
                # 88 01 01
                # Issuer Code Table Index
                # 9f11 01 01        
        
        tlv_tree = tlv_utils.parse_tlv(ret_data, known_tags=tag_meanings.emv_tags.keys())
       
        report.append('')
        for line in tlv_tree.report():
            report.append(line)    
    
        node = tlv_tree.get_nodes_for_qtag('6F.A5.88')[0]
        sfi = node.value_byte_list[0]
        
        return (sfi, tlv_tree, report)
    
    return (None, select_pse_error_tags[hex], report)

def get_application_ids_from_pse_elementary_dir_file_for_sfi(connection, sfi):
    '''
    returns aids = list of aids
    '''
    aids = []

    # READ RECORD, PASSING IN SFI RETURNED BY PSE SELECTION
    record_number = 0x01    
    
    # REFERENCE CONTROL PARAMETER
    # LSB3 => P1 is a Record Number
    # 5 high order bits used to encode SFI    
    ref_control_param = (0x04 | (sfi << 3))
    
    ret_data, sw1, sw2 = select_and_requery(connection=connection,
                                            cla=READ_RECORD.cla, 
                                            ins=READ_RECORD.ins, 
                                            p1=record_number, 
                                            p2=ref_control_param, 
                                            le=0x00)
        
    if DO_LOG:
        logging.info('\n' + 'READ RECORD [PASSING IN SHORT FILE IDENTIFIER = SFI]')
        for x in report_on_reply(sw1, sw2, ret_data):
            logging.info(x)       
    
    # 70 1a 61 18 4f 07 a0 00 00 00 04 10 10 50 0a 4d 61 73 74 65 72 43 61 72 64 87 01 01
    # 70 = [Payment System] Directory
    # 70 1a 61184f07a0000000041010500a4d617374657243617264870101
    # 61 = Directory Entry = ADF or DDF
    # 61 18 4f07a0000000041010500a4d617374657243617264870101
    # 4f = ADF Name = App ID = AID
    # 4f 07 a0000000041010
    # 50 = Application Label
    # 50 0a 4d617374657243617264 [= MasterCard]
    # 87 = Application Priority Indicator
    # 87 01 01 
    
    tlv_tree = tlv_utils.parse_tlv(ret_data, known_tags=tag_meanings.emv_tags.keys())
    
    if DO_LOG:
        logging.info('')
        for line in tlv_tree.report():
            logging.info(line)
    
    nodes = tlv_tree.get_nodes_for_qtag('70.61.4F')
    for node in nodes:
        aids.append(node.value_byte_list)   
    
    # TAG 79 => ISO 7816-6, and is part of EMV spec = Nedbank American Express
    
    return aids

def select_application_by_aid(connection, aid):
    
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=SELECT.cla, ins=SELECT.ins, p1=0x04, p2=0x00, data=aid, le=0x00)        
    
    if (len(ret_data) == 0):
        return None

    if DO_LOG:
        logging.info('\n' + 'SELECT (A)DF BY DF Name / AID')
        for x in report_on_reply(sw1, sw2, ret_data):
            logging.info(x)
   
    # Table 45 (EMV 4.2 Book 1) - FCI Returned by ADF Selection
    #
    # FCI Template
    # 6f 17 8407a0000000041010a50c500a4d617374657243617264
        # DF Name = AID
        # 84 07 a0000000041010
        # FCI PROP TEMPLATE
        # a5 0c 500a4d617374657243617264
            # APP LABEL
            # 50 0a 4d617374657243617264   

    tlv_tree = tlv_utils.parse_tlv(ret_data, known_tags=tag_meanings.emv_tags.keys())
    
    if DO_LOG:
        logging.info('')
        for line in tlv_tree.report():
            logging.info(line)
            
    return tlv_tree

def get_afl_aip_via_processing_options(connection):
    '''
    return afl or None
    
    EMV 4.2 Book 3 - 6.5.8, 6.5.8.4
    - App Interchange Profile
    - Appp File Locator
    
    EMV 4.2 Book 3 5.4 = Data Object List - DOL
    '''    
    
    # APDU = GET PROCESSING OPTIONS
    data = default_dol = [0x83, 0x00] # tag = 8300
    ret_data, sw1, sw2 = select_and_requery(connection=connection, 
                                            cla=GET_PROCESSING_OPTIONS.cla, 
                                            ins=GET_PROCESSING_OPTIONS.ins, 
                                            p1=0x00, 
                                            p2=0x00, 
                                            data=data, 
                                            le=0x00)
    
    if DO_LOG:
        logging.info('\n' + 'GET PROCESSING OPTIONS - REQUEST PDOL')
        for x in report_on_reply(sw1, sw2, ret_data):
            logging.info(x) 
    
    # 0x77 0x16 0x82 0x02 0x38 0x00 0x94 0x10 0x08 0x01 0x02 0x00 0x10 0x01 0x02 0x00 0x18 0x01 0x02 0x01 0x20 0x01 0x02 0x00
    # 77 = Format 2 Type Response
    # 77 16 82023800941008010200100102001801020120010200
    # 82 = AIP = Application Interchange Profile
    # 82 02 3800
    # 94 = AFL = Application File Locator
    # 94 10 08010200100102001801020120010200
    #
    # AFL = 08 01 02 00 
    #       10 01 02 00
    #       18 01 02 01
    #       20 01 02 00
    #                      SFI 1st Last OMA-Involved
    # 08 = 8  => 00001000 => 1  01   02           00 
    # 10 = 16 => 00010000 => 2  01   02           00 
    # 18 = 24 => 00011000 => 3  01   02           01
    # 20 = 32 => 00100000 => 4  01   02           00
    
    get_proc_options_format_1_tags = ['80']
    get_proc_options_format_2_tags = ['77', '82', '94']
    
    combined_tags = []
    combined_tags.extend(get_proc_options_format_1_tags)
    combined_tags.extend(get_proc_options_format_2_tags)
    
    tlv_tree = tlv_utils.parse_tlv(ret_data, known_tags=combined_tags)
    
    afl = None
    
    # FORMAT 1 - Visa
    if (get_proc_options_format_1_tags[0] in tlv_tree.distinct_tag_list()):
        node = tlv_tree.get_nodes_for_qtag('80')[0]
        aip_afl = node.value_byte_list
        aip_length = 2
        aip = aip_afl[0:aip_length]
        afl = aip_afl[aip_length:]     
        
        if DO_LOG:
            logging.info('AIP_AFL = ' + '.'.join(['%02X' % b for b in aip_afl]))
            logging.info('AIP     = ' + '.'.join(['%02X' % b for b in aip]))
            logging.info('AFL     = ' + '.'.join(['%02X' % b for b in afl]))
    
    # FORMAT 2 - MasterCard
    else:
        node = tlv_tree.get_nodes_for_qtag('77.94')[0]
        afl = node.value_byte_list
        node = tlv_tree.get_nodes_for_qtag('77.82')[0]
        aip = node.value_byte_list
    
    if DO_LOG:
        logging.info('')
        for line in tlv_tree.report():
            logging.info(line)
        
    return afl, aip

def verify_pin():
    raise
 
    # VERIFY PIN
    # EMV 4.2 Book 3 - 6.5.12 = VERIFY Command-Response APDUs
    
    # ref_data_qualifier = 0 # As defined in ISO/IEC 7816-4
    '''
    ref_data_qualifier = 128 # plaintext pin
    p2 = ref_data_qualifier
    
    control_field = 0x02
    pin = [8,8,8,8,8]
    orig_pin_length = len(pin)
    
    for i in range(12 - orig_pin_length):
        pin.append(0x0F)            
    
    x = (control_field << 4)
    header = (control_field << 4) | orig_pin_length
    
    data = [header]
    
    for i in range(6):
        digits = pin[i*2:i*2+2]
        combined = (digits[0] << 4) | digits[1]
        data.append(combined)
        
    tail = 0xFF            
    data.append(tail)
    
    s = 'VERIFY'
    logging.info('')
    logging.info('-'*len(s))
    logging.info(s)
    logging.info('-'*len(s))
    
    s = '.'.join(['%02X' % b for b in data]) 
    logging.info(s)
    
    # CAUTION - THIS MAY/WILL BLOCK YOUR PIN ON FIRST USE
    # ret_data, sw1, sw2 = select_and_requery(connection=connxn, cla=VERIFY.cla, ins=VERIFY.ins, p1=VERIFY.p1, p2=p2, data=data)
    for x in report_on_reply(sw1, sw2, ret_data):
        logging.info(x)
        
    # SUCCESS => 0x90 0x00
    # PIN BLOCKED => 0x69:0x83, 0x69:0x84        
    '''

def retrieve_get_data_items(connection):
    
    item_tags = [
                 
        (0x1F, 0xFF), # APP MENU OPTIONS                 
        (0xFF, 0x20),
                 
        (0x9F, 0x36), # ATC
        (0x9F, 0x13), # last online ATC register
        (0x9F, 0x17), # pin try counter
        (0x9F, 0x4F)  # log format
        
        ]
    
    tlvs = []
    
    for (p1, p2) in item_tags:
        
        tag = '%00X' % p1 + '%00X' % p2                            
        
        ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=GET_DATA.cla, ins=GET_DATA.ins, p1=p1, p2=p2, le=0x00)

        if (len(ret_data) == 0):
            logging.info('%s - sw1:sw2 = %s:%s' % (tag, '%00X' % sw1, '%00X' % sw2))
            continue
        
        tlv = tlv_utils.parse_tlv(ret_data, known_tags=tag_meanings.emv_tags.keys())
        
        tlvs.append(tlv)
        
    return tlvs

def execute_challenge(connection):
        
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=GET_CHALLENGE.cla, ins=GET_CHALLENGE.ins, p1=GET_CHALLENGE.p1, p2=GET_CHALLENGE.p2, le=GET_CHALLENGE.le)

    if DO_LOG:
        logging.info('\n' + 'GET CHALLENGE' + '\n')
        for x in report_on_reply(sw1, sw2, ret_data):
            logging.info(x) 
        logging.info('H: ' + '.'.join(['%02X' % b for b in ret_data]))
        logging.info('D: ' + '.'.join(['%i' % b for b in ret_data]))

    if (sw1, sw2) == (0x90, 0x00):
        return ret_data
    else:
        return None

def get_challenge_supported(connection):
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=GET_CHALLENGE.cla, ins=GET_CHALLENGE.ins, p1=GET_CHALLENGE.p1, p2=GET_CHALLENGE.p2, le=GET_CHALLENGE.le)
    return (sw1, sw2) == (0x90, 0x00)        

def read_transaction_logs(connection):

    if DO_LOG:
        s = 'TRANSACTION LOGS'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
    
    for sfi in range(11, 31):
        for record_number in range(0, 31):       
        
            ref_control_param = (sfi << 3) | 0x04                
            ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=READ_RECORD.cla, ins=READ_RECORD.ins, p1=record_number, p2=ref_control_param, le=0x00)
    
            if (len(ret_data) > 0):
                
                if DO_LOG:
                    logging.info('\n' + 'READ RECORD - sfi = %i, rec_num = %i' % (sfi, record_number))
                    logging.info(('.'.join(['%02X' % b for b in ret_data]) + ' ' + '.'.join(['%s' % b for b in ret_data])))

def generate_summary_report():
    '''
    logging.info('\n')
    logging.info('-'*120)
    logging.info('SUMMMARY REPORT')
    logging.info('-'*120)
    logging.info('\n')
    
    for tlv_tree in tlv_trees:
    for line in tlv_tree.report_csv(delim=','):
        logging.info(line)
    '''
    pass

def get_pse_aid_appname(connection):
    '''
    call get_pse_sfi(connection)
    if not successful,
      return []
    if SFI is successfully located
      then parse SFI to get the list of AIDs
      for each AID extracted from SFI
        attempt lookup in terminal AID list to obtain terminal reference name
        regardless, append AID to aid_appname [= list of tuple (AID, application name if found in lookup else None)]  
    return aid_appname [= list of tuple (AID, application name if found in lookup else None)]
    '''
    
    aid_appname = []
    (sfi, tlv_tree, report) = get_pse_sfi(connection)    
    
    if sfi:
        for aid in get_application_ids_from_pse_elementary_dir_file_for_sfi(connection, sfi):
            
            app_name = '?'
            aid_str = ''.join('%02X' % x for x in aid)
            matching_app_names = [x for x in aid_dict.aids.keys() if aid_dict.aids[x] in aid_str]
            if len(matching_app_names) > 0:
                app_name = ','.join(matching_app_names)
            
            logging.info('application \'%s\' found' % app_name)
            aid_appname.append((aid, app_name))
    else:
        error_message = tlv_tree
        logging.info('PSE not found. [error = %s]' % error_message)
    
    return aid_appname

def report_on_application_usage_control(app_usage_control_bytes):
    
    app_usage_control_byte_1_flags = {
        128 : 'Valid for domestic cash transactions',
        64 : 'Valid for international cash transactions',
        32 : 'Valid for domestic goods',
        16 : 'Valid for international goods',
        8 : 'Valid for domestic services',
        4 : 'Valid for international services',
        2 : 'Valid at ATMs',
        1 : 'Valid at terminals other than ATMs'
    }
    
    app_usage_control_byte_2_flags = {
        128 : 'Domestic cashback allowed',
        64 :  'International cashback allowed',
        32 :  'RFU',
        16 :  'RFU',
        8 :   'RFU',
        4 :   'RFU',
        2 :   'RFU',
        1 :   'RFU'
    }
    
    report = []
    
    for k in app_usage_control_byte_1_flags:
        if (k & app_usage_control_bytes[0] == k):
            report.append(app_usage_control_byte_1_flags[k])
    for k in app_usage_control_byte_2_flags:
        if (k & app_usage_control_bytes[1] == k):
            report.append(app_usage_control_byte_2_flags[k])

    return report

def update_report_on_cv_rule(cvm_byte_1, cvm_byte_2, report):
       
    lower_5_lsb = cvm_byte_1 & 31
    
    cvm_byte_1_5_lsb_cases = {
        0 : 'Fail CVM processing',
        1 : 'Plaintext PIN verification performed by ICC',
        2 : 'Enciphered PIN verified online',
        3 : 'Plaintext PIN verification performed by ICC and signature (paper)',
        4 : 'Enciphered PIN verification performed by ICC',
        5 : 'Enciphered PIN verification performed by ICC and signature (paper)',
        30 : 'Signature (paper)',
        31 : 'No CVM required',
    }
    
    if lower_5_lsb in cvm_byte_1_5_lsb_cases:
        report.append('cvm method = %s' % cvm_byte_1_5_lsb_cases[lower_5_lsb])
    
    cvm_byte_2_meaning = {
        0x00 : 'Always',
        0x01 :  'If unattended cash',
        0x02 :  'If not unattended cash and not manual cash and not purchase with cashback',
        0x03 :  'If terminal supports the CVM',
        0x04 :   'If manual cash',
        0x05 :   'If purchase with cashback',
        0x06 :   'If transaction is in the application currency and is under X value',
        0x07 :   'If transaction is in the application currency and is over X value',
        0x08 :   'If transaction is in the application currency and is under Y value',
        0x09 :   'If transaction is in the application currency and is over Y value',
    }
    
    for k in cvm_byte_2_meaning:
        if (k == cvm_byte_2):
            report.append('CVM condition = %s' % cvm_byte_2_meaning[k])
            break

    s = 'proceed to next rule if unsuccessful ?  '
    if (cvm_byte_1 & 64 == 64):
        report.append(s + 'Apply succeeding CV Rule if this CVM is unsuccessful')
    else:
        report.append(s + 'Fail cardholder verification if this CVM is unsuccessful')

def report_on_card_holder_verification_method(cvm_byte_list):
    
    report = []    
    amount_x = cvm_byte_list[0:4]
    amount_y = cvm_byte_list[4:8]
    rule_bytes = cvm_byte_list[8:]
    
    report.append('amt x = %s' % str(amount_x))
    report.append('amt y = %s' % str(amount_y))
    
    report.append('')
    
    for i in range(len(rule_bytes) / 2):
        bytes = rule_bytes[2*i:2*i+2]
        report.append('rule %i' % (i + 1))
        update_report_on_cv_rule(bytes[0], bytes[1], report)
        report.append('')
        
    report.pop(len(report) - 1)
    return report

def issuer_code_table_index_meaning(ict_index):
    
    ict_index_meaning = {
        1 : 'Part 1 of ISO/IEC 8859 - Latin-1 - Western European',
        2 : 'Part 2 of ISO/IEC 8859 - Latin-2 - Central European',
        3 : 'Part 3 of ISO/IEC 8859 - Latin-3 - South European',
        4 : 'Part 4 of ISO/IEC 8859 - Latin-4 - North European',
        5 : 'Part 5 of ISO/IEC 8859 - Latin/Cyrillic',
        6 : 'Part 6 of ISO/IEC 8859 - Latin/Arabic',
        7 : 'Part 7 of ISO/IEC 8859 - Latin/Greek',
        8 : 'Part 8 of ISO/IEC 8859 - Latin/Hebrew',
        9 : 'Part 9 of ISO/IEC 8859 - Latin-5 - Turkish',
        10 : 'Part 10 of ISO/IEC 8859 - Latin-6 - Nordic'
        }
    
    if ict_index in ict_index_meaning:
        return ict_index_meaning[ict_index]
    else:
        return 'no match'    

def read_record_for_sfi(connection, sfi, record_number):
    '''
    returns tlv_tree or None
    '''
    
    tlv_tree = None
    
    ref_control_param = (sfi << 3) | 0x04
            
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=READ_RECORD.cla, ins=READ_RECORD.ins, p1=record_number, p2=ref_control_param, le=0x00)
    
    if DO_LOG:
        logging.info('\n' + 'READ RECORD')
        for x in report_on_reply(sw1, sw2, ret_data):
            logging.info(x)
    
    tlv_tree = tlv_utils.parse_tlv(ret_data, known_tags=tag_meanings.emv_tags.keys())
    
    if DO_LOG:
        logging.info('')
        for line in tlv_tree.report():
            logging.info(line)
    
    # PARSE DOL FIELDS                    
    for tag_str in tlv_tree.distinct_tag_list():
        if (tag_str in tag_meanings.DOL_TAGS):
            node = tlv_tree.get_nodes_for_tag(tag_str)[0]
            dol_info = tlv_utils.parse_concatted_dol_list(node.value_byte_list)
            
            if DO_LOG:
                s = 'DOL List: %s - %s' % (tag_str, tag_meanings.emv_tags[tag_str])
                logging.info('-'*len(s))
                logging.info(s)
                logging.info('-'*len(s))
                for dol_tag in dol_info.keys():
                    logging.info('%s - %s - 0x%00X' % (dol_tag, tag_meanings.emv_tags[dol_tag], dol_info[dol_tag]))

    return tlv_tree


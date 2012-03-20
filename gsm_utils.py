# ------------------------------------------------------------------------------------------
# DIFFERENCES BETWEEN GSM AND EMV
# Class Byte = A0 for GSM
# ------------------------------------------------------------------------------------------

# logging
import logging
import log_util

# pyscard
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.ATR import ATR
from smartcard.Exceptions import NoCardException
from smartcard.Exceptions import CardConnectionException

import apdu
import chip_interrogator as chip

def select_and_requery(connection=None, cla=None, ins=None, p1=None, p2=None, lc=None, data=None, le=None):
    
    initial_reply_data, initial_sw1, initial_sw2 = chip.select(connection=connection, cla=cla, ins=ins, p1=p1, p2=p2, lc=lc, data=data, le=le)
    
    # SW1 = 0x61 => retrieve data using GET RESPONSE command
    if (initial_sw1 == 0x9F):
        return chip.select(connection=connection, cla=0xA0, ins=0xC0, p1=0x00, p2=0x00, le=initial_sw2)
    # SW1 = 0x6c => retrieve data by repeating initial command
    elif (initial_sw1 == 0x6C):
        return chip.select(connection=connection, cla=cla, ins=ins, p1=p1, p2=p2, lc=lc, data=data, le=initial_sw2)
    # initial response indicates other error
    else:
        return (initial_reply_data, initial_sw1, initial_sw2)


def report_on_chv_status(chv):
    
    if isinstance(chv, list):
        chv = chv[0]
    
    report = []
    
    num_false_presentations_remaining = (chv & 15)
    report.append('num_false_presentations_remaining = %i' % num_false_presentations_remaining)
    
    secret_code_init_status = 'secret code initialised ' if (chv & 128 == 128) else 'secret code not initialised'
    report.append('secret_code_init_status = %s' % secret_code_init_status)
    
    rfu = chv & (16 + 32 + 64)
    report.append('rfu %i' % rfu)

    return report


def report_on_mf_df_select(ret_data):
    
    report = []
    
    try:
        rfu_1 = ret_data[0:2]
        report.append('rfu_1 %s' % str(rfu_1))
        
        non_alloc_mem = ret_data[2:4]
        report.append('non_alloc_mem %s' % str(non_alloc_mem))
        
        file_id = ret_data[4:6]
        report.append('file_id %s' % '.'.join(['%02X' % x for x in file_id]))
        
        type_of_file = ret_data[6:7]
        report.append('type_of_file %s' % str(type_of_file))
        
        rfu_2 = ret_data[7:12]
        report.append('rfu_2 %s' % str(rfu_2))
        
        data_len = ret_data[12:13]
        report.append('data_len %s' % str(data_len))
        
        gsm_specific = ret_data[13:]
        report.append('gsm_specific [len = %i] = %s ' % (len(gsm_specific), str(gsm_specific)))
        
        file_characteristics = ret_data[13:14]
        report.append('file_characteristics %s' % str(file_characteristics))
        chv1_enabled = (file_characteristics[0] & 128) == 128
        report.append('- CHV1 Enabled ? %s' % chv1_enabled)    
        
        num_child_DFs = ret_data[14:15]
        report.append('num_child_DFs %s' % str(num_child_DFs))
        
        num_child_EFs = ret_data[15:16]
        report.append('num_child_EFs %s' % str(num_child_EFs))
        
        num_child_CHVs = ret_data[16:17]
        report.append('num_child_CHVs %s' % str(num_child_CHVs))
        
        rfu_3 = ret_data[17:18]
        report.append('rfu_3 %s' % str(rfu_3))
        
        chv1_status = ret_data[18:19]
        report.append('chv1_status %s' % str(chv1_status))    
        for line in report_on_chv_status(chv1_status): report.append(line)
        
        unblock_chv1_status = ret_data[19:20]
        report.append('unblock_chv1_status %s' % str(unblock_chv1_status))
        for line in report_on_chv_status(unblock_chv1_status): report.append(line)
        
        chv2_status = ret_data[20:21]
        report.append('chv2_status %s' % str(chv2_status))
        for line in report_on_chv_status(chv2_status): report.append(line)
        
        unblock_shv2_status = ret_data[21:22]
        report.append('unblock_shv2_status %s' % str(unblock_shv2_status))
        for line in report_on_chv_status(unblock_shv2_status): report.append(line)
        
        rfu_4 = ret_data[22:23]
        report.append('rfu_4 %s' % str(rfu_4))
        
        res_for_admin_manage = ret_data[23:]    
        report.append('res_for_admin_manage %s' % str(res_for_admin_manage))        

        return report

    except IndexError:    
        return report   

def interrogate(connection):
    
    atr_data = connection.getATR()    
    atr_str = '.'.join(['%00X' % x for x in atr_data])    
    logging.info('ATR:  %s [%i bytes]' % (atr_str, len(atr_data)))    
    
    # MF = 3F00
    # DF GSM = 7F20 (7F21)
    # DF ICCID = 2FE2
    # DF IMSI = 6F07
    # DF Telecom = 7F10
    # EF Phase = 6FAE
    mf_data=[0x3F, 0x00]
    df_gsm_data = [0x7F, 0x20]
    imsi_data = [0x6F, 0x07]
    icc_data=[0x2F, 0xE2]
    
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=0xA0, ins=0xA4, p1=0x00, p2=0x00, data=mf_data, le=0x00)
    report = apdu.report_on_reply(sw1, sw2, ret_data)
    logging.info('----------------------------------------------')
    logging.info('MF')
    for line in report: print(line)
    for line in report_on_mf_df_select(ret_data):
        logging.info(line)

    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=0xA0, ins=0xA4, p1=0x00, p2=0x00, data=icc_data, le=0x00)
    report = apdu.report_on_reply(sw1, sw2, ret_data)
    logging.info('----------------------------------------------')
    logging.info('ICC')
    for line in report: print(line)
    for line in report_on_mf_df_select(ret_data): logging.info(line)

    
    
    '''
    logging.info('')
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=0xA0, ins=0xA4, p1=0x00, p2=0x00, data=icc_data, le=0x00)
    report = chip.report_on_reply(sw1, sw2, ret_data)
    for line in report: print(line)
    # 10.1 Contents of the EFs at the MF level
    
    logging.info('')
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=0xA0, ins=0xA4, p1=0x00, p2=0x00, data=df_gsm_data, le=0x00)
    report = chip.report_on_reply(sw1, sw2, ret_data)
    for line in report: print(line)
    
    logging.info('')
    ret_data, sw1, sw2 = select_and_requery(connection=connection, cla=0xA0, ins=0xA4, p1=0x00, p2=0x00, data=imsi_data, le=0x00)
    report = chip.report_on_reply(sw1, sw2, ret_data)
    for line in report: print(line)
    '''
 
    
    
    

    

        

def locate_chips_and_interrogate():
    
    reader_list = chip.get_readers()
    
    if (len(reader_list) == 0):
        logging.info('no smart card reader found.')
        return

    readers_with_cards = []

    logging.info('[%i] readers present.' % len(reader_list))
    for i in range(len(reader_list)):
        reader = reader_list[i]        
        
        got_card_str = 'no card'
        if chip.card_is_present_in_reader(reader):
            got_card_str = 'card is present'
            readers_with_cards.append(reader)
        
        logging.info('reader %i - %s : card present%s' % (i + 1, reader.name, got_card_str))
    
    if readers_with_cards:    
        for reader in readers_with_cards:
            logging.info('using card found in %s' % reader.name)
            connxn = chip.get_connected_connection_for_reader(reader)
            interrogate(connxn)            
            connxn.disconnect()
    else:
        logging.info('no card found in any reader')

def main():
    log_util.init_logging(file_name='logs/chip')
    try:
        locate_chips_and_interrogate()
    except CardConnectionException:
        logging.info('card connection error')

if __name__ == '__main__':
    main()
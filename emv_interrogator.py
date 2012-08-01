from emv_utils import *
from tag_categories import tag_report, template_tags

def log_header(msg, logging_fn, header_char='-'):
    logging_fn('='*len(s))
    logging_fn(s)
    logging_fn('='*len(s))

def log_header_with_space(msg, logging_fn, header_char='-'):
    log_header(msg, logging_fn, header_char)

def interrogate(connection):
    
    aid_appname = []
    
    aid_appname = get_pse_aid_appname(connection)
    
    # PSE Not Found => Probably Visa, need to get explicitly using AID from terminal list
    if (len(aid_appname) == 0):
        for app_name in aid_dict.aids:
            
            aid = unhexlify(aid_dict.aids[app_name])
            aid = [ord(x) for x in aid]
            
            aid_appname.append((aid, app_name))
    
    failed_aids = []
    for (aid, app_name) in aid_appname:
        
        tlvs_for_app = []
        
        tlv = select_application_by_aid(connection, aid)
        if not tlv:
            failed_aids.append(aid)
            continue
        tlvs_for_app.append(tlv)
        
    # Table 45 (EMV 4.2 Book 1) - FCI Returned by ADF Selection

    # FCI Template
    # 6f 17 8407a0000000041010a50c500a4d617374657243617264
        # DF Name = AID
        # 84 07 a0000000041010
        # FCI PROP TEMPLATE
        # a5 0c 500a4d617374657243617264
            # APP LABEL
            # 50 0a 4d617374657243617264  
        
        
        app_label = tlv.values_for_tag_as_ascii_strings('50')[0]
        aid_str = tlv.values_for_tag_as_hex_strings('84')[0]
        
        logging.info('')
        s = 'App Label = \'%s\', AID = %s, Terminal Lookup Name = %s' % (app_label, aid_str, app_name)
        logging.info('='*len(s))
        logging.info(s)
        logging.info('='*len(s))
        logging.info('')
        
        # FIRST CHECK IF THE FCI CONTAINS A PDOL
        
        pdol = None
        pdols = tlv.values_for_tag('9F38')
        if (len(pdols) > 0):
            pdol = pdols[0]
        
        # AFL - APPLICATION FILE LOCATOR, APL - APPLICATION INTERCHANGE PROFILE
        
        afl, aip_byte_list = get_afl_aip_via_processing_options(connection, pdol)
        
        aip = AIP(aip_byte_list)
        aip_report = aip.report()
        
        locator = ApplicationFileLocator(afl)
    
        get_data_tlvs = retrieve_get_data_items(connection)
        tlvs_for_app.extend(get_data_tlvs)
    
        '''    
        process LOG FORMAT DOL
        if (p1, p2) == (0x9F, 0x4F): 
        pairs = tlv_utils.parse_concatted_dol_list(tlv.get_nodes_for_tag('9F4F')[0].value_byte_list)
        for tag in pairs.keys():
            logging.info('%s - %s - 0x%00X' % (tag, tag_meanings.emv_tags[tag], pairs[tag])) 
        '''
        
        record_report = []
        for loc in locator.locations:
            sfi = loc.sfi
            record_report.append('SFI %i - 1st rec %i, last rec %i' % (loc.sfi, loc.first_record_number, loc.last_record_number))
            for record_number in range(loc.first_record_number, loc.last_record_number + 1):
                tlv = read_record_for_sfi(connection, sfi, record_number)
                tlvs_for_app.append(tlv)
                
        collected_tags = {}
        for tlv in tlvs_for_app:
            tags = tlv.distinct_tag_list()
            for tag in tags:
                if tag == '' or tag == None:
                    continue
                if tag not in collected_tags:
                    collected_tags[tag] = []
                collected_tags[tag].extend(tlv.values_for_tag(tag))
        
        tags_to_exclude = []
        tags_to_exclude.extend(template_tags)
        
        tag_col, meaning_col, a_col, h_col, d_col = [], [], [], [], []
        
        # ---------------------------------------------------------------------------------------------
        # AGGREGATED TAGS SORTED BY TAG
        
        for tag in sorted(collected_tags):
            if tag not in tags_to_exclude:
                for value_bytes in collected_tags[tag]:
                    h = '.'.join(['%02X' % b for b in value_bytes])
                    a = ''.join([chr(b) if (b >= 31) else '-' for b in value_bytes])
                    d = '.'.join([str(b) for b in value_bytes])
                    meaning = tag_meanings.emv_tags[tag]
                    
                    tag_col.append(tag)
                    meaning_col.append(meaning)
                    a_col.append(a)
                    h_col.append(h)
                    d_col.append(d)

        tag_col_width = max([len(x) for x in tag_col])
        meaning_col_width = max([len(x) for x in meaning_col])
        a_col_width = max([len(x) for x in a_col])
        d_col_width = max([len(x) for x in d_col])
        h_col_width = max([len(x) for x in h_col])
        
        spc = 2

        '''
        
        s = 'AGGREGATED TAG REPORT - sorted by tag'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
        logging.info('')    

        for i in range(len(tag_col)):
            tag = tag_col[i]
            meaning = meaning_col[i]
            a = a_col[i]
            d = d_col[i]
            h = h_col[i]
            
            left_text = tag.ljust(tag_col_width + spc) + meaning.ljust(meaning_col_width + spc) 
            
            logging.info(left_text + 'A: ' + a)
            logging.info(' '*len(left_text) + 'H: ' + h)
            logging.info(' '*len(left_text) + 'D: ' + d)
        
        '''
        # -------------------------------------------------------------------------------
        
        s = 'AIP = Application Interchange Profile'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
   
        for line in aip_report:
            logging.info(line)
        logging.info('')        
        
        reported_tags = []
        for tag_cat in sorted(tag_report):
            tags = tag_report[tag_cat]
            logging.info('-'*len(tag_cat))
            logging.info(tag_cat)
            logging.info('-'*len(tag_cat))
            for tag in tags:
                if tag in collected_tags:
                    reported_tags.append(tag)
                    value_bytes_list = collected_tags[tag]
                    for value_bytes in value_bytes_list: 
                        tag_format = tags[tag]
                        meaning = tag_meanings.emv_tags[tag]
                        left_text = tag.ljust(tag_col_width + spc) + meaning.ljust(meaning_col_width + spc)                    
                        s = ''
                        len_txt = ' %3i ' % len(value_bytes)
                        if tag_format == 'A':
                            s = left_text + len_txt + 'Asc ' + ''.join([chr(b) if (b >= 31) else '-' for b in value_bytes])
                        elif tag_format == 'H':                    
                            s = left_text + len_txt + 'Hex ' + '.'.join(['%02X' % b for b in value_bytes])
                        elif tag_format == 'D':                    
                            s = left_text + len_txt + 'Dec ' +  '.'.join([str(b) for b in value_bytes])
                        logging.info(s)         
            
                        # SPECIFIC REPORTING
            
                        if tag == '9F11':
                            ict_meaning = issuer_code_table_index_meaning(value_bytes[0])
                            logging.info(' '*len(left_text) + '%s' % ict_meaning)
            
            
            logging.info('')       
            
        unreported_tags = [x for x in collected_tags.keys() if (x not in reported_tags) and (x not in template_tags)]
        
        # ----------------------------------------------------------------------------------------
        # UNCATEGORISED TAGS
        s = 'Uncategorised Fields'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
        for tag in unreported_tags:
            logging.info('%s - %s' % (tag, tag_meanings.emv_tags[tag])) 
            
       # ----------------------------------------------------------------------------------------
        # PARSE DOL FIELDS                    

        s = 'DATA OBJECT LISTS - DOLs'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))

        for tag in sorted(collected_tags):
            if (tag in tag_meanings.DOL_TAGS):
                value_bytes_list = collected_tags[tag][0]
                dol_info, repeated_dol_tags = tlv_utils.parse_concatted_dol_list(value_bytes_list)
                
                logging.info('')
                
                s = 'DOL List: %s - %s [%i items]' % (tag, tag_meanings.emv_tags[tag], len(dol_info))
                logging.info('-'*len(s))
                logging.info(s)
                logging.info('-'*len(s))
                for dol_tag in sorted(dol_info.keys()):
                    info = dol_info[dol_tag]
                    logging.info(dol_tag.ljust(6) + tag_meanings.emv_tags[dol_tag].ljust(50) + ' 0x%02X'  % info)
                    
                repeated_tag_str = '; '.join([('%s x %i' % (t, repeated_dol_tags[t])) for t in repeated_dol_tags])
                logging.info('\n[ repeated items = ' + (repeated_tag_str if len(repeated_dol_tags) > 0 else 'none') + ' ]')
        
        # ----------------------------------------------------------------------------------------
        # Application Usage Control
        
        if ('9F07' in collected_tags) or ('9F07' in unreported_tags):
            app_usage_control_bytes = collected_tags['9F07'][0]
            app_usage_report = report_on_application_usage_control(app_usage_control_bytes)
        
        s = '\nApplication Usage Control'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
   
        for line in sorted(app_usage_report):
            logging.info(line)
        logging.info('')
        
        # ----------------------------------------------------------------------------------------
        # 8E - Cardholder Verification Method (CVM) List
        
        if ('8E' in collected_tags) or ('8E' in unreported_tags):
            cvm_byte_list = collected_tags['8E'][0]
            cvm_report = report_on_card_holder_verification_method(cvm_byte_list)
        
        s = 'CVM'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
        logging.info('')
        for line in cvm_report:
            logging.info(line)
        logging.info('')
        
        # ----------------------------------------------------------------------------------------
        # GET CHALLENGE SUPPORTED ?
        
        s = 'GET CHALLENGE Supported ? %s' % str(get_challenge_supported(connection) == True)
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
        
        # ----------------------------------------------------------------------------------------
        # TXN LOG                                    

        # parse_transaction_log_records(format_str, log_rec_strings)

        s = 'Transaction Log'
        logging.info('-'*len(s))
        logging.info(s)
        logging.info('-'*len(s))
        
        log_format_tag = '9F4F'
        
        if (log_format_tag not in collected_tags):
            logging.info('Not Present')
        else:
            log_format_byte_list = collected_tags[log_format_tag][0]
            log_format_string = bit_tools.byte_list_to_hex_string(log_format_byte_list)
            
            log_records = read_transaction_logs(connection)
            log_rec_strings = [bit_tools.byte_list_to_hex_string(log_rec) for log_rec in log_records]
            
            (header, lines) = parse_transaction_log_records(log_format_string, log_rec_strings)
            
            logging.info(header)
            for line in lines:
                logging.info(line)
                
def locate_chips_and_interrogate():
    
    reader_list = chip_utils.get_readers()
    
    if (len(reader_list) == 0):
        logging.info('no smart card reader found.')
        return

    readers_with_cards = []

    logging.info('[%i] readers present.' % len(reader_list))
    for i in range(len(reader_list)):
        reader = reader_list[i]        
        
        got_card_str = 'no card'
        if chip_utils.card_is_present_in_reader(reader):
            got_card_str = 'card is present'
            readers_with_cards.append(reader)
        
        logging.info('reader %i - %s : %s' % (i + 1, reader.name, got_card_str))
    
    if readers_with_cards:    
        for reader in readers_with_cards:
            logging.info('using card found in %s' % reader.name)
            connxn = chip_utils.get_connected_connection_for_reader(reader)
            interrogate(connxn)            
            connxn.disconnect()
    else:
        logging.info('no card found in any reader')

def main():
    log_util.init_logging(file_name='/logs/emv')
    try:
        locate_chips_and_interrogate()
    except CardConnectionException:
        logging.info('card connection error')

if __name__ == '__main__':
    main()
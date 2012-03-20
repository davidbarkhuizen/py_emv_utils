import logging
import log_util
DO_LOG = False

import tag_meanings
import tag_types
from tlvnode import TlvNode
from tlvtree import TlvTree

MSB_MASK = 128
BIT_6_MASK = 32

def is_constructed_tag(tag):
    # tag is constructed if bit 6 is set
    first_tag_byte = tag[0]
    return ((first_tag_byte & BIT_6_MASK) == BIT_6_MASK)

def tag_byte_list_to_tag_str(tag_byte_list):
    return ''.join(['%02X' % b for b in tag_byte_list])

def parse_tag(tlv, known_tags=None):
    
    # determine tag, types = Extended, Simple   
    
    if not known_tags:
        known_tags = []
    
    tlv = tlv[:]
    if DO_LOG: logging.info('tlv = ' + '.'.join(['%02X' % b for b in tlv]))
    
    # considering first byte
    first_tag_byte = tlv.pop(0)    
    # are 5 LSBs all set ?
    bit_mask = 0x1F
    is_extended = ((first_tag_byte & bit_mask) ==  bit_mask) 
    
    extended_tag_bytes = []
    if is_extended:
        # not all set => simple tag => tag = byte
        # all set => keep popping bytes until MSB of popped byte not set
        #    extended tag = first byte + set of subsequent bytes, with last byte in tag having MSB not set
        
        popped_byte = 0xFF
        # keep popping until MSB is not set
        while ((popped_byte & MSB_MASK) == MSB_MASK):
            popped_byte = tlv.pop(0)
            extended_tag_bytes.append(popped_byte)
    
    tag = [first_tag_byte]
    tag.extend(extended_tag_bytes)

    if (tag_byte_list_to_tag_str(tag) not in known_tags):
        return [], []
    
    if DO_LOG: logging.info('TAG = ' + '.'.join(['%02X' % b for b in tag]))    
    
    return (tag, tlv)

def parse_length_value_remainder(byte_string):
    
    if (len(byte_string) == 0):
        return None    
    
    if DO_LOG: logging.info('parsing parse_length_value_remainder = ' + '.'.join(['%02X' % b for b in byte_string]))
     
    # read first byte of length
    
    first_length_byte = byte_string.pop(0)
    if DO_LOG: logging.info('first_length_byte : 0x%02X = %i' % (first_length_byte, first_length_byte))
    
    '''# length types = Complex, Simple'''
    '''# complex if MSB is set'''    
    is_complex = ((first_length_byte & MSB_MASK) == MSB_MASK)
    if DO_LOG: logging.info('is complex ? %s' % str(is_complex))
    
    length_bytes = []
    value_bytes = []
    remainder_bytes = []
    
    if not is_complex:
        length_bytes.append(first_length_byte)
        
        for i in range(first_length_byte):        
            try:
                b = byte_string.pop(0)
                value_bytes.append(b)
            except IndexError:
                return [], [], []
            
        remainder_bytes.extend(byte_string)
    
    # length is complex
    else:
        '''# if MSB set, then 7 LSBs define the number of subsequent bytes to read that describe length'''    
        length_byte_count = first_length_byte ^ MSB_MASK
        
        if (length_byte_count == 0):
            return [], [], []        
        
        if DO_LOG: logging.info('length_byte_count %i' % length_byte_count)
        length_bytes.append(first_length_byte)
        length_nword = []
        for i in range(length_byte_count):
            b = byte_string.pop(0)
            length_bytes.append(b)
            length_nword.append(b)

        length = length_nword[0]
        
        if DO_LOG:  logging.info('length ' + '.'.join(['%02X' % x for x in length_nword]) + ' = %i' % length)
        '''# !! !! !! !! !! !! !!'''
        
        for i in range(length):
            value_bytes.append(byte_string.pop(0))
        
        remainder_bytes.extend(byte_string)
        
    if DO_LOG:  logging.info('value_bytes ' + '.'.join(['%02X' % x for x in value_bytes]))
    if DO_LOG:  logging.info('length = %i' % len(value_bytes))
    if DO_LOG:  logging.info('remainder_bytes ' + '.'.join(['%02X' % x for x in remainder_bytes]))           
    
    return (length_bytes, value_bytes, remainder_bytes)

def parse_tlv(tlv, known_tags=None, tlv_tree=None, parent_node=None):

    if (len(tlv) <= 2):
        return
    
    if not known_tags:
        known_tags = []

    if not tlv_tree:
        tlv_tree = TlvTree()
        
    tag, length_value_remainder = parse_tag(tlv, known_tags=known_tags)
    if (len(tag) == 0) or (len(length_value_remainder) == 0):
        return
    
    (length, value, remainder) = parse_length_value_remainder(length_value_remainder)
    if (len(length) == 0) or (len(value) == 0):
        return

    tag_string = tag_byte_list_to_tag_str(tag)
    
    if tag_string not in known_tags:
        return
    
    if not parent_node:
        tlv_tree.root_node = TlvNode(tlv_tree=tlv_tree)
        parent_node = tlv_tree.root_node
    
    node = TlvNode(tlv_tree, tag_byte_list=tag, value_byte_list=value, parent_node=tlv_tree.root_node, child_nodes=[])
    parent_node.add_child_node(child_node=node)
    
    # PEERS
    if len(remainder) > 0:
        parse_tlv(remainder, known_tags=known_tags, tlv_tree=tlv_tree, parent_node=parent_node)

    # CHILDREN
    
    tag_is_constructed = is_constructed_tag(tag) 
    if (tag_is_constructed):
        if DO_LOG:  logging.info('tag %s is constructed ? %s' % (tag_string, str(tag_is_constructed)))
        parse_tlv(value, known_tags=known_tags, tlv_tree=tlv_tree, parent_node=node)
 
    '''
    print('tag [tag length = %i]' % len(tag))
    print(' '.join([hex(b) for b in tag]))
    print('length_value_remainder %s' % length_value_remainder)
    print(' '.join([hex(b) for b in length_value_remainder]))
    '''
    
    if (parent_node == tlv_tree.root_node):
        return tlv_tree

def parse_concatted_dol_list(clist):
    
    dols_by_tag = {}
    repeated_tag_counts = {}
    
    rem = clist[:]
    
    while (len(rem) > 0):
        tag, remainder = parse_tag(rem, known_tags=tag_meanings.emv_tags.keys())
        if (len(tag) == 0) or (len(remainder) == 0):
            break
        value = remainder.pop(0)
        # synchronise outer var
        for i in range(len(tag) + 1):
            rem.pop(0)
        
        tag_string = tag_byte_list_to_tag_str(tag)
        
        # record repeats
        if (tag_string in dols_by_tag):
            if (tag_string in repeated_tag_counts):
                repeated_tag_counts[tag_string] = repeated_tag_counts[tag_string] + 1
            else:
                 repeated_tag_counts[tag_string] = 1        
        
        dols_by_tag[tag_string] = value
        
    return dols_by_tag, repeated_tag_counts

def get_unqualified_tag(qualified_tag):
    if ('.' not in qualified_tag):
        return qualified_tag
    else:
        reversed = qualified_tag[::-1]
        rev_tag = reversed[:reversed.find('.')]
        return rev_tag[::-1]

def parse_and_report(tlv, known_tags=None):    
    tags = parse_tlv(tlv, known_tags=known_tags)    
    report = []
    for tag in tags.keys():
        report.append(tag.ljust(16) + tag_meanings.tags[get_unqualified_tag(tag)].ljust(60) + '.'.join(['%02X' % b for b in tags[tag]]))
    return report

def report(tags, known_tags=None):
    report = []
    
    max_tag_length = 0
    max_meaning_length = 0
    for tag in tags.keys():
        if (len(tag) > max_tag_length):
            max_tag_length = len(tag) 
        meaning = tag_meanings.tags[get_unqualified_tag(tag)]
        if (len(meaning) > max_meaning_length):
            max_meaning_length = len(meaning)
    
    for tag in sorted(tags.keys()):
        left_text = tag.ljust(max_tag_length + 2) + tag_meanings.tags[get_unqualified_tag(tag)].ljust(max_meaning_length + 2) + ('(%i) ' % len(tags[tag])).ljust(10)
        report.append(left_text + 'H: ' + '.'.join(['%02X' % b for b in tags[tag]]))
        right_text = 'A: ' + ''.join([chr(b) if (b >= 31) else '-' for b in tags[tag]])
        if (len(right_text) > 0):
            report.append(' '*len(left_text) + right_text)
    return report

tag_6f = [0x6f,0x19,0x84,0x0e,0x31,0x50,0x41,0x59,0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,0x46,0x30,0x31,0xa5,0x07,0x88,0x01,0x01,0x9f,0x11,0x01,0x01]
tag_70_simple = [0x70,0x54,0x5F,0x25,0x03,0x11,0x12,0x01,0x5F,0x24,0x03,0x17,0x02,0x28,0x9F,0x07,0x02,0xFF,0x00,0x5A,0x08,0x52,0x22,0x50,0x24,0x60,0x90,0x28,0x81,0x5F,0x34,0x01,0x00,0x8E,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x42,0x01,0x41,0x03,0x42,0x03,0x5E,0x03,0x1F,0x03,0x9F,0x0D,0x05,0xB8,0x60,0xF4,0x80,0x00,0x9F,0x0E,0x05,0x00,0x10,0x08,0x00,0x00,0x9F,0x0F,0x05,0xB8,0x68,0xF4,0x98,0x00,0x5F,0x28,0x02,0x07,0x10,0x9F,0x4A,0x01,0x82]
tag_70_extended = [0x70,0x81,0x93,0x90,0x81,0x90,0x64,0x8A,0xBC,0x88,0xB2,0x17,0x78,0x06,0xA3,0x8E,0x14,0x78,0x6B,0xCA,0x3F,0x4A,0x66,0xBE,0x6C,0x98,0x56,0x7D,0x34,0xF4,0x6E,0x1F,0x32,0x97,0x87,0x42,0x0D,0x16,0x72,0x25,0x97,0x42,0x17,0x0D,0x2F,0x90,0x6A,0xE7,0x08,0xA1,0xF7,0xD5,0xB3,0x1E,0x55,0xC1,0xD2,0xC6,0xFA,0x33,0xF1,0x86,0xAE,0xFA,0x3F,0xEA,0xE6,0x12,0x45,0x81,0xBD,0x49,0x7E,0xBE,0x67,0xB1,0x9D,0xC2,0x10,0x8B,0xD7,0x37,0x99,0xDE,0xA2,0x61,0x5A,0x9B,0x87,0x34,0xAD,0x25,0x44,0xCF,0x2F,0xFB,0x24,0xAF,0xA9,0x10,0xAA,0x2B,0x8D,0x5A,0x7A,0x68,0x70,0xE1,0xB9,0x04,0xFC,0xBB,0x2C,0xC5,0x70,0x77,0xD0,0xBC,0xF3,0x21,0x54,0x6A,0xA4,0x62,0xCD,0xAB,0xBF,0x85,0xCC,0x97,0xA4,0xD5,0x28,0x8D,0x73,0xDE,0x30,0x86,0xD9,0xE7,0x0E,0xD7,0x1C,0xE0,0xD5,0xDE,0x2D,0x88,0xFD,0x80]


if (__name__ == '__main__'):
    log_util.init_logging(file_name='../../logs/tlv')
    logging.info('\ntag_70_simple')
    parse_and_report(tag_70_simple)
    logging.info('\ntag_70_extended')
    parse_and_report(tag_70_extended)
    logging.info('\ntag_6f')
    parse_and_report(tag_6f)
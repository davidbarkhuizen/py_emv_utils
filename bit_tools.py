import binascii

MASK_FOR_BIT = {}
for i in range(8):
    MASK_FOR_BIT[i + 1] = pow(2, i)

class BitFlag(object):
    def __init__(self, byte_num, bit_num, description):
        '''
        bit_num : LSB = 1, MSB = 8
        byte_num : for byte string of n bytes, first byte = 1, last byte = n
        '''
        self.byte_num = byte_num
        self.bit_num = bit_num
        self.description = description

def hex_string_to_byte_list(hex_string):
    # convert hex string to byte list
    byte_list = []
    for i in range(len(hex_string) / 2):
        hex_byte_string = hex_string[i*2:i*2+2]
        b = binascii.unhexlify(hex_byte_string) 
        byte_list.append(ord(b))    
    return byte_list

def byte_list_to_ascii_string(byte_list):
    return ''.join([chr(b) if (b >= 31) else '-' for b in byte_list])

def byte_list_to_hex_string(byte_list):
    return ''.join(['%02X' % b for b in byte_list])

def byte_list_to_decimal_string(byte_list):                    
    return ''.join([str(b) for b in byte_list])

def bit_flag_is_set_in_byte_list(byte_list, flag):
    target_byte = byte_list[flag.byte_num - 1]
    
    bit_mask = MASK_FOR_BIT[flag.bit_num] 
    return ((target_byte & bit_mask) == bit_mask)

class CompositeBitFlag(object):
    def __init__(self, byte_num, bit_nums, description, descriptions_for_values):
        '''
        '''
        self.byte_num = byte_num
        self.bit_nums = bit_nums
        self.description = description
        self.descriptions_for_values = descriptions_for_values
   
    def evaluate_on_byte_list_and_report(self, byte_list):
        
        report = []
        
        target_byte = byte_list[self.byte_num - 1]
        
        # BUILD UP AGGREGATE MASK
        mask = 0
        for bit_num in self.bit_nums:
           bit_mask = MASK_FOR_BIT[bit_num]
           mask = (mask | bit_mask) 
         
        # APPLY AGGREGATE MASK
        shadowed_byte = (target_byte & mask) 
        
        if shadowed_byte not in self.descriptions_for_values:
            print('%i not in %s' % (shadowed_byte, str(self.descriptions_for_values.keys())))
            raise

        report.append('%s : %s' % (self.description, self.descriptions_for_values[shadowed_byte]))
        
        return report
    
class Nibble(object):
    
    def __init__(self, byte_num, least_significant, description):
        
        self.byte_num = byte_num
        
        self.least_significant = least_significant
        if self.least_significant:
            self.bit_nums = [1,2,3,4]
        else:
            self.bit_nums = [5,6,7,8]
        
        self.description = description
        
    def evaluate_on_byte_list_and_report(self, byte_list):
        
        report = []
        
        target_byte = byte_list[self.byte_num - 1]
        
        processed_byte = None
        
        # BUILD UP AGGREGATE MASK
        mask = 0
        for bit_num in self.bit_nums:
           bit_mask = MASK_FOR_BIT[bit_num]
           mask = (mask | bit_mask) 
         
        # APPLY AGGREGATE MASK
        shadowed_byte = (target_byte & mask) 
        
        if (self.least_significant == False):
            processed_byte = shadowed_byte >> 4
        else:
            processed_byte = shadowed_byte
        
        report.append('%s : %i' % (self.description, processed_byte))
        
        return report


        
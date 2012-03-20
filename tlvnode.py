import tag_meanings
import tag_types

class TlvNode(object):
    
    def __init__(self, tlv_tree=None, tag_byte_list=None, value_byte_list=None, parent_node=None, child_nodes=None):
        
        self.tlv_tree = tlv_tree
        self.parent_node = parent_node
        
        self.tag_byte_list = tag_byte_list
        self.value_byte_list = value_byte_list
                
        if child_nodes:
            self.child_nodes = child_nodes
        else:
            self.child_nodes = []
                        
    def tag_string(self):
                
        if (self.tag_byte_list):
            return ''.join(['%02X' % b for b in self.tag_byte_list])
        else:
            return ''
    
    def qualified_tag_string(self):

        if not self.parent_node:
            return self.tag_string()
        else:
            parent_str = self.parent_node.qualified_tag_string()
            if (parent_str != ''):
                parent_str = parent_str + '.'
            return  parent_str + ''.join(['%02X' % b for b in self.tag_byte_list])
    
    def add_child_node(self, child_node):
                
        self.child_nodes.append(child_node)
        child_node.parent_node = self
    
    def depth(self):
        return len([x for x in self.qualified_tag_string() if x == '.'])
        
    def __str__(self):
        
        if (self.parent_node == None):
            return ''
        
        tag = self.tag_string()    
        qtag = self.qualified_tag_string()
        
        left_text = qtag.ljust(20) + tag_meanings.emv_tags[tag].ljust(60) + ('(%i)' % len(self.value_byte_list)).ljust(5) + ' '*2
        s = left_text + 'H: ' + '.'.join(['%02X' % b for b in self.value_byte_list])
        
        right_text = ''.join([chr(b) if (b >= 31) else '-' for b in self.value_byte_list])
        if (len(right_text) > 0):
            
            first_tag_byte = self.tag_byte_list[0]
            tag_number = first_tag_byte & 31 
            tag_number_str = '%02X' % tag_number            
            tag_type_str = ''#tag_types.map_tag_number_to_type[tag_number_str]
            s = s + '\n' + tag_type_str + ' '*(len(left_text) - len(tag_type_str)) + 'A: ' + right_text 
        
        right_text = '.'.join([str(b) for b in self.value_byte_list])
        if (len(right_text) > 0):
            s = s + '\n' + ' '*len(left_text) + 'D: ' + right_text 
        
        return s
    
    def report(self, lines, with_header=True):
        
        tag = self.tag_string()
        if tag != '' and tag != None:

            if with_header and (self.depth() == 0):
                s = '%s - %s' % (tag, tag_meanings.emv_tags[tag])
                lines.append('-'*60)
                lines.append(s)
                lines.append('-'*60)
            else:    
                s = str(self)
                lines.append(s)
        
        for child in self.child_nodes:
            child.report(lines, with_header=with_header)
        
        return lines
    
    def report_csv(self, lines, delim=','):
        
        tag = self.tag_string()
        if tag != '' and tag != None:
            # qtag, tag, tag_meaning, len, hex, dec, ascii
            qtag = self.qualified_tag_string()
            tag_str = self.tag_string()
            meaning = tag_meanings.emv_tags[tag_str]
            hex = '.'.join(['%02X' % b for b in self.value_byte_list])
            ascii = ''.join([chr(b) if (b >= 31) else '-' for b in self.value_byte_list])
            dec = '.'.join([str(b) for b in self.value_byte_list])
            len_str = str(len(self.value_byte_list))
            
            s = delim.join([qtag, tag_str, meaning, len_str, hex, ascii, dec])
            
            lines.append(s)
        
        for child in self.child_nodes:
            child.report_csv(lines, delim=delim)
        
        return lines
    
    def get_nodes_for_qtag(self, qtag):
        matches = []
        if self.qualified_tag_string() == qtag:
            matches.append(self)
        for child in self.child_nodes:
            child_matches = child.get_nodes_for_qtag(qtag)
            for child_match in child_matches:
                matches.append(child_match)
        return matches
    
    def get_nodes_for_tag(self, tag):
        matches = []
        if self.tag_string() == tag:
            matches.append(self)
        for child in self.child_nodes:
            child_matches = child.get_nodes_for_tag(tag)
            for child_match in child_matches:
                matches.append(child_match)
        return matches
    
    def update_distinct_tag_list(self, tag_list):
        if (self.tag_string() not in tag_list):
            tag_list.append(self.tag_string())
        for child in self.child_nodes:
            child.update_distinct_tag_list(tag_list)
    
    
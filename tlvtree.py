class TlvTree(object):
    
    def __init__(self, root_node=None):
        self.root_node = root_node        
        
    def report(self, with_header=True):
        lines = []
        self.root_node.report(lines, with_header=with_header)
        return lines    
    
    # qtag, tag, tag_meaning, hex, dec, ascii
    
    def report_csv(self, delim=','):
        lines = []
        self.root_node.report_csv(lines, delim=delim)
        return lines
    
    def get_nodes_for_qtag(self, qtag):        
        return self.root_node.get_nodes_for_qtag(qtag)
    
    def get_nodes_for_tag(self, tag):        
        return self.root_node.get_nodes_for_tag(tag)
    
    def values_for_tag(self, tag):
        nodes = self.root_node.get_nodes_for_tag(tag)
        return [x.value_byte_list for x in nodes]
    
    def values_for_qtag(self, qtag):
        nodes = self.root_node.get_nodes_for_qtag(qtag)
        return [x.value_byte_list for x in nodes]
    
    def values_for_tag_as_ascii_strings(self, tag):
        nodes = self.root_node.get_nodes_for_tag(tag)
        values = [x.value_byte_list for x in nodes]
        if len(values) > 0:
            return [''.join([chr(x) for x in values[0]])] 
        else:
            return []
    
    def values_for_qtag_as_ascii_strings(self, qtag):
        nodes = self.root_node.get_nodes_for_qtag(qtag)
        values = [x.value_byte_list for x in nodes]
        if len(values) > 0:
            return [''.join([chr(x) for x in values[0]])] 
        else:
            return []
    
    def values_for_tag_as_hex_strings(self, tag):
        nodes = self.root_node.get_nodes_for_tag(tag)
        values = [x.value_byte_list for x in nodes]
        if len(values) > 0:
            return ['.'.join(['%02X' % x for x in values[0]])] 
        else:
            return []
    
    def values_for_qtag_as_hex_strings(self, qtag):
        nodes = self.root_node.get_nodes_for_qtag(qtag)
        values = [x.value_byte_list for x in nodes]
        if len(values) > 0:
            return ['.'.join(['%02X' % x for x in values[0]])] 
        else:
            return []
    
    def distinct_tag_list(self):
        tag_list = []
        self.root_node.update_distinct_tag_list(tag_list)
        return tag_list


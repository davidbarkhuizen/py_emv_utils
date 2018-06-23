class FileLocation(object):
    def __init__(self, sfi=None, first_record_number=None, last_record_number=None, oma_involved=None, raw_string=None):
        self.sfi = sfi
        self.first_record_number = first_record_number
        self.last_record_number = last_record_number
        self.oma_involved = oma_involved
        self.raw_string = raw_string

    def __str__(self):
        s = 'sfi = %i, 1st rec num = %i, last rec num = %i, oma-involved = %i' % (self.sfi, self.first_record_number, self.last_record_number, self.oma_involved)
        return s
    
    #logging.info('.'.join(['%02X' % x for x in file_loc_string]))
    #logging.info('len AFL = %i' % len(afl))

class ApplicationFileLocator(object):
    
    def __init__(self, afl): 
       
        loc_strings = []
        for i in range(len(afl) // 4):
            loc_strings.append(afl[i*4:i*4+4])
   
        self.locations = []   
        for loc_string in loc_strings:
            
            sfi = loc_string[0] >> 3
            first_rec_num = loc_string[1]
            last_rec_num = loc_string[2]
            oma_involved = loc_string[3]
            
            loc = FileLocation(sfi=sfi, first_record_number=first_rec_num, last_record_number=last_rec_num, oma_involved=oma_involved)
            self.locations.append(loc)
        
    def __str__(self):
        s = '\n'.join([str(loc) for loc in self.locations])
        return s
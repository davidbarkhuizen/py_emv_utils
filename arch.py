# rar archiving script
# david.barhuizen@gmail.com

# recurses subdirectories
# selectively includes only files with file extensions specified by FILE_EXTS
# creates archive named APP_NAME_yyyy-mm-dd-hh-mm

from datetime import datetime
import os

APP_NAME = 'py_emv_utils'
FILE_EXTS = ['py', 'txt', 'sql', 'bat', 'html', 'sh', 'dia', '_png', 'js', 'project', 'pydevproject'] 
FOLDER_PREFIX = '../'

def shell(cmd):
  return os.system(cmd)

def files_of_type_present(filenames, file_ext):
  for fname in filenames:
    ext = fname[len(fname) - len(file_ext) : len(fname)]    
    if (ext == file_ext):
      return True
  return False  

def time_stamp():
  now  = datetime.now()
  tstamp = '%d-%d-%d-%d-%d' % (now.year, now.month, now.day, now.hour, now.minute)
  return tstamp  

def archive():
  '''
  walk sub-branches from root location
  check if files of any target extension type are present in subfolder
  if present, add files of ext type to archive
  '''
  date_str = time_stamp()
  fname = FOLDER_PREFIX + ('%s_%s' % (APP_NAME, date_str))
  info = os.walk('.')
  for (dirpath, dirnames, filenames) in info:
    for ext in FILE_EXTS:
      if files_of_type_present(filenames, ext):
        cmd = (r'rar a -r %s ' % fname) + dirpath + '/*.' + ext
        shell(cmd)

if __name__ == '__main__':
  archive()
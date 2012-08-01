DO_LOG = True

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

from apdu import *

COL_WIDTH = 30

def get_readers():   
     
    reader_list = []    
    for reader in readers():
        reader_list.append(reader)
    return reader_list

def card_is_present_in_reader(reader):    
    card_is_present = True    
    try:
        connection = reader.createConnection()
        connection.connect()
        connection.disconnect()
    except NoCardException:
        card_is_present = False    
    return card_is_present

def get_connected_connection_for_reader(reader):
    connection = None
    try:
        connection = reader.createConnection()
        connection.connect()
    except NoCardException:
        pass
    return connection

def report_on_pyscard_atr(pyscard_atr):    
    report = []    
    report.append('BitRateFactor ' + str(pyscard_atr.getBitRateFactor()))
    report.append('Checksum ' + str(pyscard_atr.getChecksum()))
    report.append('ClockRateConversion ' + str(pyscard_atr.getClockRateConversion()))
    report.append('GuardTime ' + str(pyscard_atr.getGuardTime()))
    report.append('HistoricalBytes ' + str())
    
    hist_bytes = pyscard_atr.getHistoricalBytes()
    hist_byte_str = '.'.join(['%00X' % x for x in hist_bytes])
    report.append('HistoricalBytesCount ' + hist_byte_str)
    
    report.append('InterfaceBytesCount ' + str(pyscard_atr.getInterfaceBytesCount()))
    report.append('ProgrammingCurrent ' + str(pyscard_atr.getProgrammingCurrent()))
    report.append('ProgrammingVoltage ' + str(pyscard_atr.getProgrammingVoltage()))
    report.append('SupportedProtocols ' + str(pyscard_atr.getSupportedProtocols()))
    report.append('TA1 ' + str(pyscard_atr.getTA1()))
    report.append('TB1 ' + str(pyscard_atr.getTB1()))
    report.append('TC1 ' + str(pyscard_atr.getTC1()))
    report.append('TD1 ' + str(pyscard_atr.getTD1()))
    report.append('hasTA ' + str(pyscard_atr.hasTA))
    report.append('hasTB ' + str(pyscard_atr.hasTB))
    report.append('hasTC ' + str(pyscard_atr.hasTC))
    report.append('hasTD ' + str(pyscard_atr.hasTD))
    report.append('T0 Supported ? ' + str(pyscard_atr.isT0Supported()))
    report.append('T15 Supported ?  ' + str(pyscard_atr.isT15Supported()))
    report.append('T1 Supported ? ' + str(pyscard_atr.isT1Supported()))
    return report

def interrogate(connection):
    pass
            
def locate_chips_and_interrogate():
    
    reader_list = get_readers()
    
    if (len(reader_list) == 0):
        logging.info('no smart card reader found.')
        return

    readers_with_cards = []

    logging.info('[%i] readers present.' % len(reader_list))
    for i in range(len(reader_list)):
        reader = reader_list[i]        
        
        got_card_str = 'no card'
        if card_is_present_in_reader(reader):
            got_card_str = 'card is present'
            readers_with_cards.append(reader)
        
        logging.info('reader %i - %s : card present%s' % (i + 1, reader.name, got_card_str))
    
    if readers_with_cards:    
        for reader in readers_with_cards:
            logging.info('using card found in %s' % reader.name)
            connxn = get_connected_connection_for_reader(reader)
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


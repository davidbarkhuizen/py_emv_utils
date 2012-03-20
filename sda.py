from binascii import unhexlify, hexlify

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA

import logging
from log_util import init_logging

def dot_sep_hex_string_to_byte_list(dot_string):
    hex_byte_list = dot_string.split('.')
    return [ord(unhexlify(x)) for x in hex_byte_list]

issuer_pub_key_cert_dot_string = '0C.4F.B4.DC.50.77.F4.B2.39.E9.38.0F.71.D0.64.5E.C8.0D.B6.62.3A.FF.79.F3.27.6E.62.36.2A.FC.53.FB.5F.F4.CA.EB.EF.51.D8.D6.6D.E8.C0.EC.AA.F5.6F.A0.0A.F4.8E.3B.27.D7.4D.4D.D6.38.6E.4C.E4.11.CB.44.FD.F8.F0.6D.9B.1D.32.75.78.13.A7.1A.7E.D9.48.B3.BE.17.17.84.C0.22.06.22.3C.4A.3A.C0.7D.6F.32.23.A4.62.04.3E.F6.97.1C.20.FD.81.5C.15.A4.35.7F.9D.D1.28.C3.DF.0A.4C.BE.A0.F0.8A.37.8E.71.42.98.7C.63.56.9A.05.5A.88.9F.E2.9E.B9.41.1B.31.CB.52.3A'
issuer_pub_key_cert_byte_list = dot_sep_hex_string_to_byte_list(issuer_pub_key_cert_dot_string)
issuer_pub_key_cert_hex_string = issuer_pub_key_cert_dot_string.replace('.', '')
issuer_pub_key_cert = long(issuer_pub_key_cert_hex_string, 16)

icc_pub_key_cert_dot_string = '7C.C2.18.6A.67.CA.A6.F1.6D.EA.40.B9.64.D1.82.F1.83.0E.72.C4.01.75.A8.F3.AB.32.FD.38.13.B9.92.3C.E5.A8.57.13.5B.AA.33.B0.11.BD.A5.9C.60.6A.BB.33.34.EB.97.2A.6D.CD.72.07.EC.ED.7B.D5.44.D8.C3.48.88.14.14.B3.12.34.40.28.CE.FC.BE.BA.4F.B3.99.F0.C0.58.FA.12.60.CB.64.A1.CF.56.51.60.E0.FA.B0.9A.AA.E4.34.32.61.B3.AA.DE.3E.92.4E.E5.AF.96.BE.6D.AD.39.A0.E8.23.8D.8D.B6.26.0D.2E.D7.9B.FE.22.80.68.C5.D6.A6.85.A5.3E.5E.50.AA.70.B7.97.A2.F9.BB'
icc_pub_key_cert_byte_list = dot_sep_hex_string_to_byte_list(icc_pub_key_cert_dot_string)
icc_pub_key_cert_hex_string = icc_pub_key_cert_dot_string.replace('.', '')
icc_pub_key_cert = long(icc_pub_key_cert_hex_string, 16)


ca_modulus_byte_list = [0xA8,0x9F,0x25,0xA5,0x6F,0xA6,0xDA,0x25,0x8C,0x8C,0xA8,0xB4,0x04,0x27,0xD9,0x27,
    0xB4,0xA1,0xEB,0x4D,0x7E,0xA3,0x26,0xBB,0xB1,0x2F,0x97,0xDE,0xD7,0x0A,0xE5,0xE4,
    0x48,0x0F,0xC9,0xC5,0xE8,0xA9,0x72,0x17,0x71,0x10,0xA1,0xCC,0x31,0x8D,0x06,0xD2,
    0xF8,0xF5,0xC4,0x84,0x4A,0xC5,0xFA,0x79,0xA4,0xDC,0x47,0x0B,0xB1,0x1E,0xD6,0x35,
    0x69,0x9C,0x17,0x08,0x1B,0x90,0xF1,0xB9,0x84,0xF1,0x2E,0x92,0xC1,0xC5,0x29,0x27,
    0x6D,0x8A,0xF8,0xEC,0x7F,0x28,0x49,0x20,0x97,0xD8,0xCD,0x5B,0xEC,0xEA,0x16,0xFE,
    0x40,0x88,0xF6,0xCF,0xAB,0x4A,0x1B,0x42,0x32,0x8A,0x1B,0x99,0x6F,0x92,0x78,0xB0,
    0xB7,0xE3,0x31,0x1C,0xA5,0xEF,0x85,0x6C,0x2F,0x88,0x84,0x74,0xB8,0x36,0x12,0xA8,
    0x2E,0x4E,0x00,0xD0,0xCD,0x40,0x69,0xA6,0x78,0x31,0x40,0x43,0x3D,0x50,0x72,0x5F]
ca_modulus_hex_string  = ''.join(['%02X' % x for x in ca_modulus_byte_list])
ca_modulus = long(ca_modulus_hex_string, 16)

ca_exp = long(0x03)

def main():

    init_logging(file_name='logs/sda')

    logging.info('CA Modulus, length = %i' % len(ca_modulus_byte_list))
    logging.info(ca_modulus_hex_string)
    
    ca_pub_key = RSA.construct((ca_modulus, ca_exp))
    (clear_text,) = ca_pub_key.encrypt(issuer_pub_key_cert, None)

    
    print('LONG - Clear Text')
    print(clear_text)
    print('HEX - Clear Text')
    s = '%02X' % clear_text
    print(s)
    print(len(s))
    
    dot_string = '3D.AE.88.08.1C.9E.C5.92.54.11.B3.47.E5.C4.80.31.07.0F.C4.A1.A0.10.2A.53.83.A2.94.B7.9C.4A.FA.51.FB.CF.7C.55.96.0E.B4.65.68.EF.AA.BA.D6.24.79.0A.3A.55.17.0D.80.4F.2D.6E.E2.56.AE.D6.EF.E6.8F.C1.4B.02.12.FD.98.90.8E.E4.67.A2.30.F7.BC.47.40.F2.DA.7F.F0.40.A9.18.49.E0.83.D4.77.DC.46.E8.A1.25.02.91.51.A7.2D.7C.1A.FC.88.36.FD.D9.4E.14.17.3F.0B.00.5C.EC.87.17.09.71.8F.6C.7A.88.1F.02.25.44.52.79.BA.B9.38.C8.72.89.32.6E.C7.98.15.C8.4C.D5'
    signed_data = dot_sep_hex_string_to_byte_list(dot_string)
    logging.info('Signed Static Data, length = %i' % len(signed_data))
    logging.info(signed_data)

    
    


if (__name__ == '__main__'):
    main()
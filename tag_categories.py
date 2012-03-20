
template_tags = ['61', '6F', '70', '71', '72', '73', '77', '80', '83', 'A5']

tag_report = {
    '1 - Application Info' : {
        '50' : 'A', # Application Label
        '5F24' : 'H', # Application Expiration Date
        '5F25' : 'H', # Application Effective Date
        '87' : 'D', # Application Priority Indicator
        '9F08' : 'D', # Application Version Number
        '9F07' : 'H', # Application Usage Control
        '9F12' : 'A', # Application Preferred Name  
        '9F44' : 'H', # Application Currency Exponent
        '9F42' : 'H', # Application Currency Code
        '5F2D' : 'H', # Language Preference
        '84': 'H', # Dedicated File (DF) Name
        },
    'ISO 7813 Mag Stripe Data' : {
        '5F30': 'H', # 'Service Code'
        '57' : 'H', # Track 2 Equivalent Data
        '9F1F' : 'H', # Track 1 Discretionary Data
        '9F20' : 'H'# Track 2 Discretionary Data        
        },
    '2 - Card & Account Info' : {
        '5A' : 'H', # Application Primary Account Number (PAN)
        '5F20' : 'A', # Cardholder Name
        '5F34' : 'D', # Application Primary Account Number (PAN) Sequence Number
        },   
    '4 - Transaction Log' : {
        '9F4F': 'H', # Log Format
        },                            
    'Issuer Info' : {
        '5F28' : 'H', # Issuer Country Code  
        '9F11' : 'D', # Issuer Code Table Index
     },
    'Issuer Action Codes (TVR Mirrors)' : {
        '9F0D': 'H', # Issuer Action Code - Default
        '9F0E': 'H', # Issuer Action Code - Denial
        '9F0F': 'H', # Issuer Action Code - Online
     },
    'Cardholder Verification & Data Authentication - SDA/DDA (CDOL = Gen AC 1,2, DDOL = Int Auth)' : {
        '93': 'H', # 'Signed Static Application Data'
        '8C' : 'H', # Card Risk Management Data Object List 1 (CDOL1)
        '8D' : 'H', # Card Risk Management Data Object List 2 (CDOL2)
        '8E': 'H', # Cardholder Verification Method (CVM) List
        '9F49' : 'H', # Dynamic Data Authentication Data Object List (DDOL)
        '9F4A' :'H', # Static Data Authentication Tag List
     },       
   'Crypto - Issuer Public Key' : {
        '90' : 'H', # Issuer Public Key Certificate
        '92' : 'H', # Issuer Public Key Remainder        
        '9F32' : 'H', # Issuer Public Key Exponent
        '8F': 'H', # Certification Authority Public Key Index
    },
    'Crypto - ICC Public Key' : {
        '9F48' : 'H', # ICC Public Key Remainder
        '9F47' : 'H', # ICC Public Key Exponent
        '9F46' : 'H', # ICC Public Key Certificate       
    },
    '3 - Counters / Registers' : {
        '9F13' : 'H', # Last Online Application Transaction Counter (ATC) Register
        '9F17' : 'H', # Personal Identification Number (PIN) Try Counter
        '9F36' : 'H', # Application Transaction Counter (ATC)     
    },
}
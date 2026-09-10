# py_emv_utils

Python utilities for interrogating EMV (chip) payment cards over a PC/SC
smartcard reader, using the [pyscard](https://github.com/LudovicRousseau/pyscard)
library.

2012 - 2018
David Barkhuizen

Parts of this code were developed using time contributed by
[Synthesis Software Technologies](http://www.synthesis.co.za/).

## Requirements

- Python 3
- A PC/SC stack (`pcscd` and drivers on Linux; built in on macOS and Windows)
- A contact smartcard reader
- [pyscard](https://github.com/LudovicRousseau/pyscard)
- [pycryptodome](https://pypi.org/project/pycryptodome/) — only for `sda.py`
  (offline data authentication); not needed for card interrogation

## Installation

### Debian / Ubuntu

```
sudo apt install pcscd
pip install pyscard
```

`python3-pyscard` from apt also works in place of `pip install pyscard`.

### macOS

```
brew install swig
pip install pyscard
```

### Windows

```
pip install pyscard
```

## Usage

Place a card on the reader and run:

```
python3 emv_interrogator.py
```

The script enumerates connected PC/SC readers, connects to the first card it
finds, and produces a decoded report covering:

- the PSE / application list and FCI for each application (AID, label, PDOL)
- Application Interchange Profile (AIP) and Application File Locator (AFL)
- every record read from the application's files, with TLV tags grouped and
  categorised, and each value shown as ASCII / hex / decimal
- decoded Application Usage Control, CVM list, TVR/TSI where present
- Data Object Lists (PDOL, CDOL1/2, DDOL, ...) expanded to their component tags
- GET CHALLENGE support and, if the card exposes a transaction log, the parsed
  log entries

Output is written both to the console and to a timestamped file under `logs/`
(e.g. `logs/emv_2018-6-23-14-5.log`). The interrogator issues only standard EMV
read commands (SELECT, GET PROCESSING OPTIONS, READ RECORD, GET DATA, GET
CHALLENGE); it does not run a transaction or attempt cardholder verification.

## Modules

| Area | Files |
| --- | --- |
| Interrogation driver | `emv_interrogator.py`, `emv_utils.py`, `chip_utils.py` |
| APDU exchange | `apdu.py` |
| TLV / BER-TLV | `tlv_utils.py`, `tlvtree.py`, `tlvnode.py` |
| EMV tag reference | `tag_meanings.py`, `tag_categories.py`, `tag_types.py` |
| Data-element parsers | `application_file_locator.py`, `application_interchange_profile.py`, `cvr_parser.py`, `tvr_parser.py`, `tsi_parser.py` |
| Reference data | `aid_dict.py`, `iso_3166_country_codes.py` |
| Helpers | `bit_tools.py`, `text_utils.py`, `log_util.py` |
| Offline data authentication | `sda.py` |

## Notes

- `sda.py` still contains Python 2 constructs (`long`) and does not run as-is
  under Python 3.
- `gsm_utils.py` (SIM/GSM helpers) and `arch.py` (a local `rar` archiving
  script) are unrelated to card interrogation and are not maintained;
  `gsm_utils.py` imports a `chip_interrogator` module that is not in this
  repository.

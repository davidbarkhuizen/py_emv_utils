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
- [pyscard](https://github.com/LudovicRousseau/pyscard) (the only Python
  dependency; also listed in `requirements.txt`)

No third-party crypto library is required; `sda.py` does its RSA recovery with
`pow()`.

## Installation

### Debian / Ubuntu

```
sudo apt install pcscd
pip install pyscard
```

`python3-pyscard` from apt also works in place of `pip install pyscard`.
`pip install -r requirements.txt` is equivalent.

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

The script enumerates connected PC/SC readers and, for every reader that has a
card, produces a decoded report covering:

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

### Behaviour worth knowing

- **Application discovery.** If the card exposes a PSE (`1PAY.SYS.DDF01`), its
  application list is read from there. If it does not, discovery falls back to a
  fixed AID list in `aid_dict.py` — an application whose AID is not in that list
  is not found.
- **GET PROCESSING OPTIONS.** When an application's PDOL asks for terminal data,
  the tool supplies the selected AID for `9F06` and zero bytes for amount fields
  and for any other requested element; that is enough for the card to return the
  AIP and AFL.
- **Terminal country.** It identifies itself as a South African terminal
  (Terminal Country Code `0710`, `emv_utils.TERMINAL_COUNTRY_CODE`). Most cards
  ignore this; change the constant if a card's geographic checks matter.

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

- `sda.py` is a standalone experiment (offline data authentication) driven by
  hard-coded sample certificates, not part of the interrogation path.
- `gsm_utils.py` (SIM/GSM helpers) and `arch.py` (a local `rar` archiving
  script) are unrelated to card interrogation and are not maintained.

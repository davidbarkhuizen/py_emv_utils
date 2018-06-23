# py_emv_utils
python EMV utilities using the pyscard smartcard interface  

2012 - 2018  
David Barkhuizen  

Parts of this code were developed using time contributed by:  
- [Synthesis Software Technologies](http://www.synthesis.co.za/)

## PreRequisites

### pyscard - python smart card library

py_emv_utils makes use of the pyscard library to interact with the smartcard at the APDU level
and so pyscard must be installed first.  

the pyscard project appears to currently be actively managed at github by Ludovic Rousseau
https://github.com/LudovicRousseau/pyscard  

it was originally authored by Jean-Daniel Aussel (http://sourceforge.net/users/jdaussel)  
and was available from sourceforge @ http://sourceforge.net/projects/pyscard/  
with a project page @ http://pyscard.sourceforge.net/  

it appears that there is a mirror of this original source available from github:  
https://github.com/sekimura/pyscard  

## Installation

### ubuntu (debian) linux

$ sudo apt install pcscd  
$ sudo apt install python-pyscard  

### osx

1. install pip  
$ pip install bdist_mpkg  

2. install swig  
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" < /dev/null 2> /dev/null  
$ brew install swig  

3. install pyscard  
$ pip install pyscard  


## Usage

$ python3 emv_interrogator.py
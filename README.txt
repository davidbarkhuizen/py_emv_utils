py_emv_utils = Python EMV Utils Using PySCard
2012
David Barkhuizen

Parts of this code were developed using time contributed by Synthesis Software Technologies [http://www.synthesis.co.za/].

PYSCARD
Python smart card library.
Written by Jean-Daniel Aussel [http://sourceforge.net/users/jdaussel]
Project Page = http://pyscard.sourceforge.net/
Download Page = http://sourceforge.net/projects/pyscard/

INSTALLATION - LINUX/UBUNTU
packages:  pcscd, python-pyscard
e.g. install from the command line via apt-get
$ sudo apt-get install pcscd
$ sudo apt-get install python-pyscard

BASIC USE CASE, from the cmd line
1. plug smart card reader into usb
2. insert smart card into reader
3. $ python emv_interrogator.py
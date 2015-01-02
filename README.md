OT7 - ONE-TIME PAD ENCRYPTION TOOL                        


DESCRIPTION: OT7 is an implementation of the one-time pad encryption method. 
It's a portable command line tool that works on many operating systems. OT7
should build with most C compilers.

Encryption is needed to protect intellectual property held on data storage 
devices and when traveling on the internet.

OT7 produces an encrypted file that remains secret when sent over unsecure 
channels.  

Features:

        - Convenient key management using a configuration file.
        - Password protection.
        - Optional key erasure for forward security.
        - Completely documented source code to make validation easier.

Requires:
        
        - C compiler and a command line environment.
        - User-generated random key files.
        
To build OT7: gcc OT7.c -o ot7

To build ot7test: gcc ot7test.c -o ot7test

January 2, 2015 status - OT7 is released for general use. It has passed the 
ot7test program on Debian (64-bit) and Mac OSX (PowerPC). 
 
LICENSE: This is public domain software. I am grateful to Edward Snowden for
revealing why encryption is necessary. Please consider donating to his defense 
fund at http://freesnowden.is . 


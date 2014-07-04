OT7.c - OT7 ONE-TIME PAD ENCRYPTION TOOL                        


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

July 4, 2014 status - Everything seems to work, but the hash function has yet 
to be validated relative to the reference design. This only has a bearing on
the password protection layer since the one-time pad encryption part is secure 
if the key is truly random and secret. OT7 has been lightly tested on Debian,
Mac OSX, and Windows.
 
LICENSE: This is public domain software. I am grateful to Edward Snowden for
revealing why encryption is necessary. Please consider donating to his defense 
fund at http://freesnowden.is . 


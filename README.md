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

December 27, 2014 status - Just fixed a string length calculation bug, so please 
upgrade to the latest version. Everything else seems to work and the hash function 
has been validated relative to the reference design. OT7 has been lightly tested 
on Debian, Mac OSX, and Windows. There are no known bugs but more testing is needed
to finalize the code. Next up is to do more testing with a bunch of randomly 
generated test files. 
 
LICENSE: This is public domain software. I am grateful to Edward Snowden for
revealing why encryption is necessary. Please consider donating to his defense 
fund at http://freesnowden.is . 


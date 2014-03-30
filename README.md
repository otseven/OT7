OT7.c - OT7 ONE-TIME PAD ENCRYPTION TOOL                        
March 29, 2014

PURPOSE: A tool and protocol for one-time pad encryption.

DESCRIPTION: OT7 is an implementation of the one-time pad encryption method. 

Encryption is needed to protect intellectual property held on data storage 
devices and when traveling on the internet.

OT7 produces an encrypted file that remains secret when sent over unsecure 
channels.  

From https://en.wikipedia.org/wiki/One_time_pad:

"In cryptography, the one-time pad (OTP) is a type of encryption that is 
impossible to crack if used correctly. Each bit or character from the plaintext 
is encrypted by a modular addition with a bit or character from a secret random 
key (or pad) of the same length as the plaintext, resulting in a ciphertext. If 
the key is truly random, as large as or greater than the plaintext, never reused 
in whole or part, and kept secret, the ciphertext will be impossible to decrypt 
or break without knowing the key."

LICENSE: This is public domain software. I am grateful to Edward Snowden for
revealing why encryption is necessary. Please consider donating to his defense 
fund at http://freesnowden.is . 

        -- THIS IS ALPHA CODE SUITABLE FOR EXPERIMENTAL USE ONLY --
           -- LIGHTLY TESTED ON DEBIAN, MAC OSX, AND WINDOWS --

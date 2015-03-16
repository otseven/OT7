OT7 - ONE-TIME PAD ENCRYPTION TOOL                        


DESCRIPTION: OT7 is an implementation of the one-time pad encryption method. 
It's a portable command line tool that works on many operating systems. 

Encryption is needed to protect property held on data storage devices and when 
traveling on the internet.

OT7 produces an encrypted file that remains secret when sent over unsecure 
channels.  

Features:

        - Flexible key management using a configuration file.
        - Password protection in case a key file is ever stolen.
        - Optional erasure of message keys after use for forward security.
        - Base64 or binary encrypted code format.
        - Encrypted code format is designed to defeat protocol analysis.
        - Optional padding bytes to hide the size of the message.
        - All working memory buffers are cleared after use.
        - Completely documented source code to make validation easier.
        - Informative return codes to support the use of OT7 in scripts.
        - Built in help function.

Requires:
        
        - C compiler and a command line environment.
        - User-generated random key files.

OT7 should build with most C compilers, with possible minor adjustments needed 
for linking file i/o routines.

        To build OT7:       gcc OT7.c -o ot7

        To build ot7test:   gcc ot7test.c -o ot7test


Here's a simple encryption example:

    1. Make a file named hello.txt containing "Hello world!".
    2. Generate a key file named 123.key. For this example, any file can be used as
       a key file by renaming it to "123.key".
    3. Encrypt the file using this command: 

          ./ot7 -e hello.txt -KeyID 123 -oe hello.b64

The encrypted message is contained in hello.b64, and looks something like this:

          Av1mMo7FOEgeSc20wbVcbju7k3/0UMkp8SlR9HbwTW+mSKOGJI8CpQP7TgO8ZaLmt965HoBuYaAW
          4SVzGlQNC8afIZ8tRuUPxw==

To decrypt the message, use this command:

          ./ot7 -d hello.b64 -KeyID 123 -od hello2.txt
     
The resulting file hello2.txt contains the original message "Hello world!".

More options are available to make using OT7 easier. 

To list the OT7 user guide, use the help command:

          ./ot7 -h
          
Or to save the user guide to a file, type:

          ./ot7 -h > help.txt

LICENSE: This is public domain software. I am grateful to Edward Snowden for
revealing why encryption is necessary. Please consider donating to his defense 
fund at http://freesnowden.is . 

January 17, 2015 status - OT7 is released for general use. It has passed the 
ot7test program on Debian (64-bit) and Mac OSX (PowerPC). 
 

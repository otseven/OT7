/* https://github.com/otseven/OT7            

          -- THIS IS BETA CODE SUITABLE FOR EXPERIMENTAL USE ONLY --
             -- LIGHTLY TESTED ON DEBIAN, MAC OSX, AND WINDOWS --
   
--------------------------------------------------------------------------------
OT7.c - OT7 ONE-TIME PAD ENCRYPTION TOOL                       November 30, 2014
--------------------------------------------------------------------------------

PURPOSE: A tool and protocol for one-time pad encryption.

DESCRIPTION: OT7 is an implementation of the one-time pad encryption method. 

Encryption is needed to protect intellectual property held on data storage 
devices and when traveling on the internet.

OT7 produces an encrypted file that remains secret when sent over unsecure 
channels.  
 
This diagram outlines the OT7 encryption process:

        Plaintext file                                   Plaintext file
                      \                                 /
                       Encrypt ---> [OT7 file] --> Decrypt
                      /                               /     
 One-time pad key file                               One-time pad key file

From https://en.wikipedia.org/wiki/One_time_pad:

"In cryptography, the one-time pad (OTP) is a type of encryption that is 
impossible to crack if used correctly. Each bit or character from the plaintext 
is encrypted by a modular addition with a bit or character from a secret random 
key (or pad) of the same length as the plaintext, resulting in a ciphertext. If 
the key is truly random, as large as or greater than the plaintext, never reused 
in whole or part, and kept secret, the ciphertext will be impossible to decrypt 
or break without knowing the key."
 
SCOPE: The OT7 protocol is limited to encryption and decryption of a defined 
file format. Production of one-time pad key files for the OT7 command line tool
is outside the scope of the OT7 protocol. Each user will need to supply their
own key files.
 
LICENSE: This is public domain software. I am grateful to Edward Snowden for
revealing why encryption is necessary. Please consider donating to his defense 
fund at http://freesnowden.is . 

--------------------------------------------------------------------------------

RECORD FORMAT: Each OT7 file is laid out according to this record format:
 
                       O T 7   R E C O R D   F O R M A T
 
                                            variable
                             24 bytes        length
                       ---------------------------------
                       |   H E A D E R   |   B O D Y   |
                       ---------------------------------
                                         |=============| ONE-TIME PAD ENCRYPTED

In more detail:
                       H E A D E R                            
          --------------------------------------  
          | HeaderKey | KeyIDHash | KeyAddress |  
          ------------+-----------+------------+ 
          0           8          16           24                             
          |             
          Byte Offset

The header contains three 64-bit fields:
 
    HeaderKey.............. 8 random bytes used for encrypting the KeyIDHash  
                            and KeyAddress fields. 

    KeyIDHash.............. Index to the one-time pad file key file used to 
                            encrypt the body of the record. 
 
    KeyAddress............. The address in the one-time pad file where the key 
                            bytes are located for decrypting the OT7 record. 
 
--------------------------------------------------------------------------------
  
The layout of the body section is shown here:
                             
                                 B O D Y
--------------------------------------------------------------// 
| H E A D E R | ExtraKeyUsed | SizeBits | TextSize | FillSize |...
--------------+--------------+----------+----------+----------+//
0            24             25         26          variable                             
|             |===================== ONE-TIME PAD ENCRYPTED =============...
Byte Offset
                                                 B O D Y (continued)
                                 //--------------------------------------------- 
                                ...| FileNameSize | FileName | TextFill | SumZ |
                                 //+--------------+----------+----------+------- 
                                   variable    
                                ...======= ONE-TIME PAD ENCRYPTED =============| 
   
--------------------------------------------------------------------------------
               F  I  E  L  D      D  E  F  I  N  I  T  I  O  N  S
--------------------------------------------------------------------------------

The fields of an OT7 record are defined as follows.
             
--------------------------------------------------------------------------------
H E A D E R
--------------------------------------------------------------------------------

The header of an OT7 record identifies the one-time pad key used to encrypt the 
record. The header is designed to appear to an attacker as random bits. Almost
every OT7 header will be unique with very rare collisions being possible. 
 
                  FIELD SIZE    
FIELD NAME         IN BYTES                DESCRIPTION
--------------------------------------------------------------------------------
HeaderKey          8 bytes      

    HeaderKey is used as an input to the computation of the KeyIDHash and 
    encrypted KeyAddress. 
    
    HeaderKey is also used to confirm that the correct one-time pad key is being 
    used when decrypting an OT7 record.
 
    The HeaderKey is a hash value computed as follows:
    
         HeaderKey = Skein1024 Hash Function{ RandomBytes, Password }
         
      where:
      
         RandomBytes is a sequence of true random bytes from the one-time pad 
         key file used to encrypt the OT7 record. The bytes are located at the
         KeyAddress.
            
         Password is the current password parameter, either entered on the
         command line, from a key definition, or from the DefaultPassword 
         compiled into the ot7 command line tool. 
    
    See the section 'KEY MAP FILE FORMAT:' for how to make key definitions.
  
--------------------------------------------------------------------------------
KeyIDHash         8 bytes 
       
    KeyIDHash is an index to the one-time pad key file used to encrypt the body 
    of the OT7 record.
    
    The KeyIDHash is a hash value computed from the following elements:
    
         KeyIDHash = Skein1024 Hash Function{ HeaderKey, KeyID, Password }
         
      where:
      
            HeaderKey is the value from the HeaderKey field of an OT7 record.
             
            KeyID identifies a key definition by number. This is a value 
            associated with the one-time pad encryption key used to encrypt the 
            OT7 record.
            
            Password is the current password parameter, either entered on the
            command line, from a key definition, or the default password.
    
    The above hashing operation produces a 128-bit output value. The first
    64-bits are used as the KeyIDHash and stored in the KeyIDHash field.
  
    Decryption involves a trial-and-error process of trying all known (KeyID,
    Password) pairs with the HeaderKey from an OT7 record until a matching 
    KeyIDHash value is found. Then the KeyID is used to locate the one-time
    pad key file for decrypting the body of the record.
     
--------------------------------------------------------------------------------
KeyAddress    8 bytes   
 
    KeyAddress is the place in a one-time pad file where key bytes are located 
    for decrypting the OT7 record. It is the byte offset from the beginning of 
    the file identified by the KeyID.
                               
    This is a 64-bit integer stored in LSB-to-MSB order and XOR'ed with the
    second 64 bits of the same 128-bit hash value used to produce the KeyIDHash.
     
--------------------------------------------------------------------------------
B O D Y
--------------------------------------------------------------------------------

All of the following fields are one-time pad encrypted and password protected.

If the one-time pad key file used to encrypt an OT7 record becomes known to an 
attacker, then a password could prevent disclosure of the plaintext.

The encrypted bytes of the body are composed of three layers of information:

             ================== ENCRYPTED BYTES ====================
                              ^  ^  ^  ^  ^
           1 ----------------- true random bytes -------------------
           2 --------------- password hash stream ------------------
           3 ------------ plaintext and filler bytes ---------------
     
Layer 1 is the true random bytes from the one-time pad key file. These are
produced by a hardware random number generator.

Layer 2 is pseudo-randomly generated by a Skein1024 hash function seeded with 
true random data from the one-time pad file and the current password.

Layer 3 is the plaintext plus any filler bytes used to obscure the size of the
plaintext.

Encrypted bytes are simply the result of XOR'ing bytes drawn from each of the
three layers.

        EncryptedByte = PlainTextByte ^ (TrueRandomByte ^ PasswordHashByte)
     
Decryption uses this formula:

        PlainTextByte = EncryptedByte ^ (TrueRandomByte ^ PasswordHashByte)
     
Like the header, the body of an OT7 record appears to an attacker as true 
random data.
             
              FIELD SIZE    
FIELD NAME     IN BYTES                 DESCRIPTION
--------------------------------------------------------------------------------
ExtraKeyUsed    1 byte

    Number of key bytes used in the one-time pad key file prior to the 
    KeyAddress. Key bytes may be used for generating the number of fill bytes. 
    These extra key bytes need to be tracked so that they can be erased along 
    with the bytes used to encrypt the OT7 record if the key erase option is 
    used on encryption or decryption.

--------------------------------------------------------------------------------
SizeBits        1 byte

    Specifies the size of the TextSize and FillSize fields. The low 4 bits is 
    the number of bytes in the TextSize field. The high 4 bits is the number 
    of bytes in the FillSize field. 
    
                     7    6    5    4     3    2    1    0
                   -----------------------------------------
                   | FillSizeFieldSize | TextSizeFieldSize |
                   -----------------------------------------
                              SizeBits Field Format

--------------------------------------------------------------------------------
TextSize        0 to 8 bytes depending on SizeBits   
    
    The size of the plaintext in bytes, an integer stored in LSB-to-MSB order. 
    Only the non-zero bytes of the integer are stored, so this field is from 0 
    to 8 bytes long as defined by the low 4 bits of the SizeBits field.
    
--------------------------------------------------------------------------------
FillSize        0 to 8 bytes depending on SizeBits     

    The number of fill bytes, an integer stored in LSB-to-MSB order. Only the 
    non-zero bytes of the integer are stored, being from 0 to 8 bytes as defined 
    by the high 4 bits of the SizeBits field. 
    
    Fill bytes are optional padding bytes used to mask the size of the 
    plaintext. By default a random number of fill bytes are used. The command 
    line option '-f' can be used to specify a certain number of fill bytes.
    
--------------------------------------------------------------------------------
FileNameSize    2 bytes      

    Size of the FileName field in bytes. This is a 16-bit integer stored in 
    LSB-to-MSB order. If this value is 0, then the FileName field is not 
    included.
    
--------------------------------------------------------------------------------
FileName        FileNameSize bytes    

    Name of the plaintext file, a printable ASCII string without a zero at the 
    end. The FileNameSize field indicates how many characters are in the string.
    
    This field can be excluded during encryption by using the '-nofilename'
    command line parameter.
    
    Note that some care is needed when decrypting a file with an embedded file 
    name to make sure that it doesn't accidentally overwrite an existing file 
    with the same name. The '-od' command line option can be used to override 
    the embedded file name, using a specified file name instead.
        
--------------------------------------------------------------------------------
TextFill        TextSize+FillSize bytes     

    The text of the message is interleaved with fill bytes, like this:

    [Text][Fill][Text]... for all of the text and fill bytes. 

    The text is the plaintext of the message and it can be any kind of data. 

    Fill bytes are padding bytes inserted to mask the size of the text. 
    
    Pseudo-random fill values are used for extra security.
 
    Fill bytes are encrypted just like all the other bytes in the body of the 
    record.
    
--------------------------------------------------------------------------------
SumZ            8 bytes     

    SumZ is a check sum over prior fields in the body of the OT7 record before 
    any encryption. This is a 64-bit integer stored in LSB-to-MSB order. The 
    header bytes and fill bytes are not included in this checksum.

    This is an integrity check used to detect the successful decryption of the
    plaintext.
    
    If the integrity check fails, the decrypted output file is still produced,
    but with an error message reporting that the contents have been corrupted.
    Media defects have a limited impact on an OT7 record if they occur in the
    TextFill field: errors are limited only to the individual bytes where they 
    occur. A media error in the fields prior to TextFill could cause the whole
    decryption process to fail.
   
    The checksum function is Skein1024.

    SumZ is the last field of an OT7 record.
                  
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
KEY FILE FORMAT 
--------------------------------------------------------------------------------

Key files have no special structure. Any file that contains random binary data 
can be used as a key file.  

It is essential to use true random numbers because the security of one-time pad 
encryption depends on the quality of the key.

Some kind of natural process is required to produce perfectly random numbers, so 
a hardware random number generator is needed. 

Since the NSA weakens commercial hardware random number generators, you should 
build your own. 

--------------------------------------------------------------------------------
KEY.MAP FILE FORMAT 
--------------------------------------------------------------------------------

'key.map' files are another source of input for the ot7 command line tool. 

A 'key.map' file provides configuration information.
 
It's called a key map because it tells where the key files are located and also 
how KeyID numbers map to one-time pad key files. 

A 'key.map' file is composed of one or more key definitions. Each key definition 
organizes the information needed to use one-time pad key files for a particular 
purpose. 
 
It may be convenient to store frequently used parameter settings as part of a 
key definition in a 'key.map' file instead of typing them on the command line.
 
Here is an example 'key.map' file that you can use as a template for your own:

//==============================================================================
//======================= BEGIN KEY.MAP FILE CONTENTS ==========================
//==============================================================================

//<---- 'key.map' files may contain comments which begin with '//' and continue  
//      to the end of the line.
//
// A 'key.map' file may contain one or more key definitions.
//
// A key definition has this form:
//
//    KeyID( 143 )
//    {
//          ...the parameters of the key...
//    }
//
// where:
//
//    '143' is the KeyID number of the key definition, the primary identifier 
//          of the definition. KeyID numbers must be unique within the 
//          'key.map' file in which they are used.
//
//    KeyID numbers can be expressed in decimal or in hexadecimal form, eg. 
//    "KeyID( 0x41ad9 )". Values can range from 0 to the largest value that 
//    can be stored in a 64-bit field, 18446744073709551616 or 
//    0xFFFFFFFFFFFFFFFF.
//
//    The KeyID is connected with the KeyIDHash the stored in the header of an 
//    OT7 record in encrypted form. 
//
//    When an OT7 record is decrypted, the KeyIDHash in the OT7 record header  
//    implies which key definition to used for decryption. This lookup procedure 
//    can be overridden by specifying that a certain KeyID be used instead with 
//    the '-KeyID <number>' command line option.
//
//    The parameters of a key definition follows a consistent format:
//
//        Each parameter is listed on a separate line. 
//
//        Each parameter begins with a parameter tag that starts with '-', for  
//        example '-keyfile' or '-ID'.
//
//        One or more spaces separate the parameter tag from any data that 
//        follows. Multi-word parameter values are enclosed in quotes.
 
// Here is an example key definition:
 
KeyID( 143 )  
{
    //--------------------------------------------------------------------------
    // K E Y   F I L E S
    //--------------------------------------------------------------------------

    // A key definition refers to a pool of one or more one-time pad key files,
    // each one listed on a separate line with the parameter tag '-keyfile'.
    
    // This is the pool of key files for this key definition:
    
    -keyfile file1.key
    -keyfile /home/myfiles/file2.key
    -keyfile some_other_file.bin
    -keyfile any_other_filename.zip
    -keyfile "a file name with spaces.key"
    
    // Each key file contains truly random bytes that are only used once. 
    // 
    // Key files need to be writable only if key bytes are erased after use by 
    // selecting the '-erasekey' option. Otherwise, key files may be read-only.
    // 
    // To complete a key definition, it is sufficient to define just one key
    // file. If several key files are used, then the ordering of the files in 
    // the key definition determines the order in which they are used for
    // encryption and decryption.
    //
    // A decryptor uses the KeyID number to look up a particular key definition. 
    // If that key definition contains multiple key files, then it may be 
    // necessary to try to decrypt using several different key files before the 
    // right one is found to successfully decrypt the message. The decryption 
    // routine automatically handles this search process, but it will be slower 
    // than using just one key file per key definition.
    
    //--------------------------------------------------------------------------
    // P A S S W O R D
    //--------------------------------------------------------------------------
     
    // Passwords provide an extra layer of security in addition to that provided 
    // by one-time pad key files. When a password is used to encrypt a file, 
    // then the same password must be used to decrypt the file.
    //
    // Passwords can be stored in key definitions or entered on the command
    // line. If a password is entered on the command line, then it overrides 
    // any password that might also be stored in a key definition. In this 
    // example, a password is stored in the key definition. 
      
    -p "This is the password for encrypting files sent to Dan Jones."
     
    // Passwords are either single words or phrases enclosed in double quotes
    // Passwords may be up to 2000 characters long. Longer passwords are more 
    // secure than shorter ones. 
    //
    // If no password is specified by the user, then the default password
    // compiled into the OT7 application is used. See DefaultPassword for where
    // that is defined.
    
    //--------------------------------------------------------------------------
    // O T H E R   O P T I O N S
    //--------------------------------------------------------------------------
    
    // For convenience, other command line options can be stored with a key 
    // definition. This extra information will automatically be presented to the 
    // command line parser each time the key is used during encryption or 
    // decryption. This allows an encryption policy to be set up once and then 
    // used simply by referring to the key definition with either the '-KeyID' 
    // or '-ID' command line options.
    //
    // Secondary identifiers can optionally be associated with a key definition 
    // to give another way to refer to a key definition. List each identifier 
    // on a separate line with the parameter tag '-ID'. Any string can be used 
    // as an identifier. A phrase can be used as an identifier by enclosing it
    // in double quotes, as shown below.
  
    -ID "Dan Jones"
    -ID danjones@privatemail.net
    -ID BM-GtkZoid3xpT4nwxezDfpWtYAfY6vgyHd
      
    // Use the '-erasekey' option if you want to erase key bytes after use.
    // -erasekey
    
    // Use the '-v' option to enable verbose mode which prints status
    // messages.
    -v
    
    // Use the '-oe' option to name the default output file used when encrypting
    // files. In this example, encrypted files are written to 'Dan.txt'. If the 
    // '-oe' option is included on the command line, it will override this 
    // default setting.
    -oe Dan.txt
  
} // End of the key definition for KeyID 143.

// There can be any number of definitions in a 'key.map' file.

// This is another definition that will be used for general purpose encryption.
KeyID( 7891 )  
{
    -keyfile general.key
    -ID general
    -p "password for general purpose encryption"
}

//==============================================================================
//======================== END KEY.MAP FILE CONTENTS ===========================
//==============================================================================

With the above 'key.map' file, it becomes possible to encrypt and decrypt a file 
named 'myfile.zip' as follows:
 
Encrypting: ot7 -e myfile.zip -oe myfile.ot7 -ID general

Decrypting: ot7 -d myfile.ot7

Here's an example of how to encrypt an email message for Dan Jones in several
different ways:
 
    ot7 -e email.txt -KeyID 143

    ot7 -e email.txt -ID "Dan Jones" 

    ot7 -e email.txt -ID danjones@privatemail.net
      
    ot7 -e email.txt -ID BM-GtkZoid3xpT4nwxezDfpWtYAfY6vgyHd

    ot7 -e email.txt -ID "Dan Jones" -p "a special password for today"

All of the above commands will encrypt the file 'email.txt' to produce an 
encrypted file named 'Dan.txt'.  

If Dan Jones has a key definition for KeyID( 143 ), then he can decrypt 
'Dan.txt' using one of these two command lines:

    ot7 -d Dan.txt

    ot7 -d Dan.txt -p "a special password for today" 

... resulting in the file 'email.txt' being produced in his current 
directory. 
 
Dan Jones may have different optional parameters for his version of the
key definition for KeyID( 143 ) provided that the same key file names 
and password are included. 
  
*/

#define APPLICATION_NAME_STRING "ot7"
            // Name of this application.
            
#define _LARGEFILE64_SOURCE
            // Enable the use of large files with sizes up to 2^64.
            
#define _FILE_OFFSET_BITS 64
            // Enable the use of 64-bit file offsets.
            
#define _LARGEFILE_SOURCE
            // Enable the use of fseeko and ftello.
            
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// For MacOS X, 64-bit file access is standard. Define the symbols needed to
// link to the library routines.
#if defined( __MWERKS__ ) || defined( __APPLE_CC__ )
    #define off64_t     off_t
    #define fopen64     fopen 
    #define fseeko64    fseek
    #define ftello64    ftell
#endif // __MWERKS__ || __APPLE_CC__

//------------------------------------------------------------------------------

// Abbreviated integer types.
typedef unsigned char    u8;         
typedef unsigned short   u16; 
typedef unsigned long    u32; 
typedef char             s8;
typedef short            s16; 
typedef long             s32;

// For 64-bit integers...
//

// ... for GCC on Linux.
#if defined( __GNUC__ ) && defined( __linux__ ) 
    typedef unsigned long long  u64;
    typedef long long           s64; 
#endif // __GNUC__
 
// ... for Metrowerks or Apple compilers.
#if defined( __MWERKS__ ) || defined( __APPLE_CC__ )
    typedef unsigned long long  u64;
    typedef long long           s64; 
#endif // __MWERKS__ || __APPLE_CC__

// ...for Microsoft Visual C++.
#if defined( _MSC_VER ) && !defined( __MWERKS__ ) && defined( _INTEGRAL_MAX_BITS ) && ( _INTEGRAL_MAX_BITS >= 64 )
    typedef unsigned __int64    u64; // VC++ doesn't fully support this type: use s64 instead.
    typedef __int64             s64;
#endif // _MSC_VER

#define MAX_VALUE_32BIT 0xFFFFFFFFL
            // The maximum value that can be held in a 32-bit field.

#define MAX_VALUE_64BIT 0xFFFFFFFFFFFFFFFFLL
            // The maximum value that can be held in a 64-bit field.

//------------------------------------------------------------------------------

// Ascii codes by name:
#define CarriageReturn  13
#define ControlZ        26 //  eof marker for DOS
#define Tab              9
#define LineFeed        10
#define FormFeed        12
#define Space           32
 
// Macros for classification of ASCII characters:
  
#define IsWhiteSpace(a) \
            ( (a) == Space          || \
              (a) == Tab            || \
              (a) == CarriageReturn || \
              (a) == LineFeed       || \
              (a) == FormFeed       || \
              (a) == ControlZ )
              
#define IsPrintableASCIICharacter(a) ( (a) >= 32 && (a) <= 126 )   

#define IsHexDigit(a)   ( ( (a) >= '0' && (a) <= '9' ) || \
                          ( (a) >= 'a' && (a) <= 'f' ) || \
                          ( (a) >= 'A' && (a) <= 'F' ) )
 
//------------------------------------------------------------------------------

// This is the default password used if none is specified with the '-p' command.
// Customize this password for improved security. If the DefaultPassword is 
// changed, then a corresponding change may also need to be made to other 
// instances of the ot7 command line tool so that decryption will work when no 
// password is specified with the '-p' option.
s8* DefaultPassword = "The right of the people to be secure in their persons, "
        "houses, papers, and effects, against unreasonable searches and "
        "seizures, shall not be violated, and no warrants shall issue, but "
        "upon probable cause, supported by oath or affirmation, and "
        "particularly describing the place to be searched, and the persons or "
        "things to be seized. ";
  
//------------------------------------------------------------------------------

#define KEY_FILE_SIGNATURE_SIZE 32
    // The number of bytes at the beginning of a one-time pad key file reserved 
    // for identifying the file. The signature bytes will not be used for 
    // encryption or erased. They are used to compute a hash used in a log file 
    // which keeps track of how many key bytes have been used in each one-time 
    // pad key file.

#define OT7_HEADER_SIZE 24
    // Number of bytes used at the beginning of an OT7 encrypted file before
    // the body of the message.
    //                             H E A D E R                            
    //                --------------------------------------  
    //                | HeaderKey | KeyIDHash | KeyAddress |  
    //                ------------+-----------+------------+ 
    //                0           8          16           24                             
    //                |             
    //                Byte Offset

#define HEADERKEY_FIELD_OFFSET  (0)               
#define HEADERKEY_FIELD_SIZE    (8)  
    // Offset and size of the HeaderKey field in an OT7 record header.
             
#define KEYIDHASH_FIELD_OFFSET  (8)    
#define KEYIDHASH_FIELD_SIZE    (8)    
    // Offset and size of the KeyIDHash field in an OT7 record header.
           
#define KEYADDRESS_FIELD_OFFSET (16)               
#define KEYADDRESS_FIELD_SIZE   (8)               
    // Offset and size of the KeyAddress field in an OT7 record header.
 
#define EXTRAKEYUSED_FIELD_SIZE (1)
    // Size of the ExtraKeyUsed field in bytes.
    
#define SIZEBITS_FIELD_SIZE (1)
    // Size of the SizeBits field in bytes.
 
#define FILENAMESIZE_FIELD_SIZE (2)
    // Size of the FileNameSize field in bytes.
    
#define SUMZ_FIELD_SIZE (8)
    // Size of the SumZ checksum field in bytes.
    
#define OT7_MINIMUM_VALID_FILE_SIZE   \
          (OT7_HEADER_SIZE +          \
           EXTRAKEYUSED_FIELD_SIZE +  \
           SIZEBITS_FIELD_SIZE +      \
           FILENAMESIZE_FIELD_SIZE +  \
           SUMZ_FIELD_SIZE)
    // The minimum number of bytes that an OT7 encrypted file can be, a value
    // used for filtering out files that are too small during decryption. 
        
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// DATA BUFFER LIMITS
//------------------------------------------------------------------------------

#define MAX_FILE_NAME_SIZE  512
    // Maximum file name size supported, in bytes.
 
#define TEXT_LINE_BUFFER_SIZE  2048
    // The maximum supported number of characters per line in a text file.
    
#define HEX_STRING_BUFFER_SIZE 4096 
    // The size in bytes of the HexStringBuffer used to format binary data for
    // printing.

//------------------------------------------------------------------------------
 
#define KEY_FILE_HASH_SIZE 8
    // The size of a one-time pad key file FileID hash in bytes. This is the 
    // size of the binary representation of the hash: the ASCII representation 
    // is twice as big.
  
#define KEY_FILE_HASH_STRING_BUFFER_SIZE 17
    // The size of a buffer for a one-time pad key file FileID hash as an ASCII 
    // string, in bytes. Each byte of the binary FileID hash expands to two 
    // ASCII hex digits and there is one byte at the end for the string 
    // terminator.
    
//------------------------------------------------------------------------------
 
#define KEYIDHASH128BIT_BYTE_COUNT (16)
    // Size of the hash that spans the KeyIDHash and KeyAddress fields of an OT7
    // record header, in bytes. Note that a KeyID hash and a FileID hash are
    // two different things.
      
//------------------------------------------------------------------------------

#define BLOCK_SIZE 512
    // For efficiency, bytes may be read from files in blocks of many bytes 
    // instead of one by one. BLOCK_SIZE determines the size of the blocks to 
    // use. 512 bytes matches the sector size used on some disk drives, so a
    // multiple of 512 bytes is probably a good choice.

#define TEXT_BUFFER_SIZE  BLOCK_SIZE
    // Size of the buffer used to hold plaintext data during encryption and
    // decryption.
    
#define FILL_BUFFER_SIZE  BLOCK_SIZE
    // Size of the buffer used to hold filler (padding) data during encryption 
    // and decryption.
 
#define TEXTFILL_BUFFER_SIZE  (TEXT_BUFFER_SIZE + FILL_BUFFER_SIZE)
    // Size of the buffer used to hold interleaved plaintext and fill bytes data 
    // during encryption and decryption of the TextFill field of an OT7 record.

#define KEY_BUFFER_SIZE  TEXTFILL_BUFFER_SIZE
    // Size in bytes of the buffers used to hold key data during encryption/
    // decryption. This buffer is the same size as the TextFillBuffer to 
    // simplify encryption and decryption routines.
    
#define KEY_BUFFER_BIT_COUNT (KEY_BUFFER_SIZE << 3)
    // Size in bits of the key buffers used for encryption and decryption.
    // This parameter is used for producing one full buffer of pseudo-random
    // data.

//------------------------------------------------------------------------------
// DATA BUFFERS
//------------------------------------------------------------------------------
 
s8 HexStringBuffer[HEX_STRING_BUFFER_SIZE]; // 4096 bytes
    // A buffer for converting bytes to printable ASCII hex digits.
 
s8 TextLineBuffer[TEXT_LINE_BUFFER_SIZE]; // 2048 bytes
    // A buffer for reading lines of text from a file.

//------------------------------------------------------------------------------
// LINKED LIST SUPPORT
//------------------------------------------------------------------------------
              
typedef struct Item     Item;
typedef struct List     List;
typedef struct ThatItem ThatItem;

/*------------------------------------------------------------------------------
| Item
|-------------------------------------------------------------------------------
|
| PURPOSE: To organize information about an item in a list.
|
| DESCRIPTION: This is a general purpose list item that supports the listing of 
| data held anywhere in memory. 
|
| By separating the links from the data being referenced it becomes possible to 
| organize any type of data record without needing to modify the record to 
| incorporate linked list fields.
|
| HISTORY: 
|    20Dec01 
|    19Nov13 Revised for OT7.
|    28Feb14 Removed unused fields.
------------------------------------------------------------------------------*/
struct Item
{
    Item* NextItem;
            // The next item in a list of items or zero if there is no next 
            // item.
            //
    Item* PriorItem;
            // The prior item in a list of items or zero if there is no previous 
            // item.
            //
    u8*   DataAddress;   
            // Location of data associated with the item. 
            //
            // This may also be the base address of a dynamically allocated 
            // buffer holding the data.
            //
            // DataAddress is set to zero if no data is associated with the 
            // item.
};
                          
/*------------------------------------------------------------------------------
| List
|-------------------------------------------------------------------------------
|
| PURPOSE: To organize information about a list.
|
| DESCRIPTION: This record defines the locations of the first and last items in
| a list and tracks how many items are in the list.
|
|                          [List]----------------- 
|                             |                  |
|                   FirstItem |                  | LastItem
|                             v                  v
|                          [Item]--->[Item]----[Item] 
|                          |                        |
|                          |<------ ItemCount ----->|
| HISTORY: 
|    20Dec01 Changed ListMark field to 32 bits from 8 bit and added Lock field. 
|    07Jul02 Changed simple lock field to LLock type.
|    21Nov13 Removed the exclusion lock.
|    28Feb14 Removed unused ListMark field.
------------------------------------------------------------------------------*/
struct List
{
    Item* FirstItem; 
            // Refers to the first item in the list or zero if there are no 
            // items in the list.
            //
    Item* LastItem;  
            // Refers to the last item in the list or zero if there are no 
            // items in the list.
            //
    u32   ItemCount; 
            // Number of items in the list.
};

/*------------------------------------------------------------------------------
| ThatItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To provide a way to refer to a single item in the context of a list.
|
| DESCRIPTION: This is an item cursor.
|
| Think of this record as a finger pointing at an item in a list to select it 
| for special processing. 
|
|            [ThatItem]---------------  
|                 |                  |
|                 v                  v
|              [List]--->[Item]----[Item]----[Item]...
|
| This record holds the context needed to refer to an item during traversal 
| through the list.
|
| HISTORY: 
|   06Jan02 From ThatRecord and ThatChar.  This record supercedes the use of 
|           the global variables TheItem, TheList and the list context stack.
------------------------------------------------------------------------------*/
struct ThatItem
{
    Item*   TheItem;  
                // Address of the current Item in the list.
                //
    List*   TheList;   
                // The current list.
};

// Tracking counters used to detect failure to deallocate a list or item. These
// counters increment each time a List or Item is allocated, and then 
// decremented each time a List or Item is deallocated.
s32 CountOfListsInUse = 0; // How many List records are in use.
s32 CountOfItemsInUse = 0; // How many Item records are in use.
       
/*------------------------------------------------------------------------------
| Param
|-------------------------------------------------------------------------------
|
| PURPOSE: To organize information about an integer crypto parameter. 
|
| DESCRIPTION: An encryption or decryption process depends on a collection of
| parameters from the command line or from a key definition.
|
| Unspecified parameters are set to default values to begin with.
|  
| Once a parameter has been set, then it applies from that point on. 
|
| If a parameter is not set from the command line, then it may be set from a key
| definition read from a 'key.map' file. 
|
| HISTORY: 
|    08Dec13 
------------------------------------------------------------------------------*/
typedef struct
{
    u32 IsSpecified;      
            // Status flag set to 1 if the parameter has been specified on the
            // command line or from a 'key.map' file, or 0 if not. 
            //
       u64 Value;
            // An integer or logic flag parameter value. 
} Param;

/*------------------------------------------------------------------------------
| ParamString
|-------------------------------------------------------------------------------
|
| PURPOSE: To organize information about a string crypto parameter. 
|
| DESCRIPTION: An encryption or decryption process depends on a collection of
| parameters from the command line or from a key definition.
|
| Unspecified parameters are set to default values to begin with.
|  
| Once a parameter has been set, then it applies from that point on. 
|
| If a parameter is not set from the command line, then it may be set from a key
| definition read from a 'key.map' file. 
|
| HISTORY: 
|    24Dec13 From Param.
------------------------------------------------------------------------------*/
typedef struct
{
    u32 IsSpecified;      
            // Status flag set to 1 if the parameter has been specified on the
            // command line or from a 'key.map' file, or 0 if not. 
            //
       s8* Value;
            // Address of a string parameter such as a file name. 
            //
            // The string is ASCII with a zero terminator byte.
            //
            // If this field refers to a data buffer, then it must persist 
            // through the encryption/decryption process and be freed by the 
            // process that allocated it.
} ParamString;

/*------------------------------------------------------------------------------
| ParamList
|-------------------------------------------------------------------------------
|
| PURPOSE: To organize information about a string list crypto parameter. 
|
| DESCRIPTION: An encryption or decryption process depends on a collection of
| parameters from the command line or from a key definition.
|
| Unspecified parameters are set to default values to begin with.
|  
| Once a parameter has been set, then it applies from that point on. 
|
| If a parameter is not set from the command line, then it may be set from a key
| definition read from a 'key.map' file. 
|
| HISTORY: 
|    24Dec13 From Param.
------------------------------------------------------------------------------*/
typedef struct
{
    u32 IsSpecified;      
            // Status flag set to 1 if the parameter has been specified on the
            // command line or from a 'key.map' file, or 0 if not. 
            //
       List* Value;
            // Address of a list of string parameters such as file names. 
            //
            // The strings are ASCII with a zero terminator byte.
            //
            // If this field refers to a data buffer, then it must persist 
            // through the encryption/decryption process and be freed by the 
            // process that allocated it.
} ParamList;

//------------------------------------------------------------------------------
// NUMERICAL AND LOGICAL PARAMETERS
//------------------------------------------------------------------------------

Param EncryptedFileFormat;
    // The encoding format to use for the encrypted OT7 file, 0 for binary or 1 
    // for base64.

    #define OT7_FILE_FORMAT_BINARY 0
    #define OT7_FILE_FORMAT_BASE64 1

Param FillSize;
    // The number of fill bytes to include in the encrypted file to mask the 
    // size of the plaintext. This is specified on the command line using the 
    // '-f' option, eg. -f 1000. If unspecified, then a random number of fill 
    // bytes from 0 to the size of the plaintext file will be used.
            
Param IsDecrypting;
    // Decryption mode flag. This is set to 1 if the decryption command '-d' is 
    // specified on the command line, or 0 if not.            
 
Param IsEncrypting;
    // Encryption mode flag. This is set to 1 if the encryption command '-e' is 
    // specified on the command line, or 0 if not.                    

Param IsEraseUsedKeyBytes;
    // Control flag set to 1 if used key bytes in the one-time pad should be
    // erased after use, or 0 if not. This is set to 1 on the command using 
    // '-erasekey' option, defaulting to 0 otherwise.
  
Param IsHelpRequested;
    // Control flag set to 1 if usage info should be printed, or 0 if not.
    // This is set to 1 on the command line using the '-h' or '-help' options.

Param IsNoFileName;
    // File name exclusion flag. This is set to 1 to exclude the file name of 
    // the plaintext file from the  OT7 record during encryption. Defaults to 
    // 0 meaning that the file name should be included.                    
 
Param IsReportingUnusedKeyBytes;
    // Control flag used to cause the reporting of available (unused) key 
    // bytes in one-time pad key files. This is set to 1 on the the command 
    // line using the '-unused' or '-u' option, defaulting to 0 otherwise.
 
Param IsTestingHash;
    // Flag used to enable running the Skein hash function test routine.
    // This is set to 1 on the command line using the '-testhash' option.
 
Param IsVerbose;
    // Verbose mode flag used to enable the printing of status messages.
    // This is set to 1 on the command line using the '-v' option.
     
Param KeyID;
    // The ID number used in an OT7 file header to identify the encryption key. 
    // When used in conjunction with a 'key.map' file, this KeyID value can 
    // be used to find the key file name for decryption. 
    //
    // If no 'key.map' file was used for encryption, then the default 
    // interpretation of the KeyID number is to convert it to a decimal number 
    // with the file extension '.key', eg. '4239832.key', and that key will
    // be used for encryption or decryption.
    //
    // One advantage of using key definitions in a 'key.map' file is that the
    // linkage between the KeyID and the key file name becomes an arbitrary 
    // connection that makes it much harder for an attacker to identify the 
    // key file name used to encrypt an OT7 file.
    
// A list of all numeric command line parameters.
Param* 
NumericParameters[] =
{
    &EncryptedFileFormat,
    &FillSize,
    &IsDecrypting,
    &IsEncrypting,
    &IsEraseUsedKeyBytes,
    &IsHelpRequested,
    &IsNoFileName,
    &IsReportingUnusedKeyBytes,
    &IsTestingHash,
    &IsVerbose,
    &KeyID,
     
    0 // List is terminated with a zero.
};

//------------------------------------------------------------------------------
// STRING PARAMETERS
//------------------------------------------------------------------------------

ParamString LogFileName;
    // Name of the log file used to track used key bytes. The default name for 
    // this file is 'ot7.log'. 
     
ParamString KeyMapFileName;
    // Name of the optional key map file that holds key definitions. The default
    // name for this file is 'key.map'. 
    
ParamString NameOfDecryptedOutputFile;
    // Name of the output file produced by a decryption process. This is 
    // specified on the command line using the '-od' option and defaults to the 
    // filename embedded in the OT7 record if there is one, or 'ot7d.out' if 
    // there is no embedded filename.             
 
ParamString NameOfEncryptedInputFile;
    // Name of an input file containing encrypted data in the form of an OT7 
    // record. This is the input to the decryption process. 

ParamString NameOfEncryptedOutputFile;
    // Name of the output file produced by an encryption process. This is 
    // specified on the command line using the '-oe' option and defaults to 
    // 'ot7e.out'.                

ParamString NameOfPlaintextFile;
    // Name of the file containing the user's plaintext. This file is the input 
    // to the encryption process as specified by the '-e' option. The default
    // plaintext file name is 'plain.txt'. 

ParamString Password;
    // The password defined on the command line or in a user's 'key.map' 
    // file. If no password is specified by the user, then the DefaultPassword 
    // value is used.  
 
// A list of all string command line parameters.
ParamString* 
StringParameters[] =
{
    &LogFileName,
    &KeyMapFileName,
    &NameOfDecryptedOutputFile,
    &NameOfEncryptedInputFile,
    &NameOfEncryptedOutputFile,
    &NameOfPlaintextFile,
    &Password,
    
    0 // List is terminated with a zero.
};

//------------------------------------------------------------------------------
// LIST PARAMETERS
//------------------------------------------------------------------------------

ParamList IDStrings;
    // A list of identifiers associated with a key definition. This provides 
    // alternative ways to refer to a key definition. Identifer parameters begin 
    // with the parameter '-ID'. Any string can be used as an identifier so long
    // as it is unique within the key map file. To put several words into an 
    // identifier use single or double quotes, as shown here:
    //
    // -ID 'Dan Jones'
    // -ID "John 'Smitty' Smith"
    // -ID danjones@privatemail.net
    // -ID BM-GtkZoid3xpT4nwxezDfpWtYAfY6vgyHd    

ParamList KeyFileNames;
    // List of names of one-time pad key files which contain random bytes. 
    // Specified on the command line using the '-keyfile' option, or indirectly 
    // via a lookup in the 'key.map' file.            

ParamList KeyMapList;
    // The contents of the key map file as a linked list of text lines. Comments
    // and whitespace are removed from the key map file as it is read into 
    // memory to make parsing easier. The IsSpecified flag of this variable is 
    // zero if the key map file could not be read.
    
ParamList LogFileList;
    // The contents of the OT7 log file as a linked list of text lines. This
    // file tracks the consumption of key bytes in one-time pad key files. It
    // is used during encryption, but not during decryption. The log file is
    // written at the end of an encryption process to update the number of 
    // used key bytes. The IsSpecified flag of this variable is zero if the log 
    // file could not be read.
         
// A list of all string list command line parameters.
ParamList* 
StringListParameters[] =
{
    &IDStrings,
    &KeyFileNames,
    &KeyMapList,
    &LogFileList,
     
    0 // List is terminated with a zero.
};
         
//------------------------------------------------------------------------------
// MULTI-FORMAT FILE I/O SUPPORT
//------------------------------------------------------------------------------

/*------------------------------------------------------------------------------
| FILEX
|-------------------------------------------------------------------------------
| 
| PURPOSE: To organize extra info about a file being read or written.
|
| DESCRIPTION: The format of an OT7 encrypted file can be either binary or
| base64. To make it more convenient to access either type of file, the state 
| info required for base64 encoding is combined with a file handle using this 
| data type.
|
| There is are some file I/O routines that use this type of structure in place 
| of a standard file handle.
|
| HISTORY: 
|    13Oct13 
|    10Nov13 Added LastSymbolRead.
------------------------------------------------------------------------------*/
typedef struct
{
    FILE* FileHandle; 
        // A standard file handle.
        //
    u8 FileFormat;
        // How the file is encoded, either binary or base64.
        // Use these codes here: OT7_FILE_FORMAT_BINARY or 
        //                       OT7_FILE_FORMAT_BASE64
        // 
    u64 FilePositionInBytes;  
        // The current byte offset from the beginning of the file.
        //
    u64 FilePositionIn6BitWords;
        // The current offset from the beginning of the file in terms of 6-bit
        // words, ignoring whitespace and padding.
        //
        // The least significant two bits of the 6-bit-word file position is
        // a word index that refers to a 6-bit word in a 24-bit field.
        // 
        // In base64 encoding, 6-bit words are packed into bytes using a
        // 4-in-3 byte arrangement as shown here:
        //
        //         word index=1
        //               |
        //            -------
        //      00000011 11112222 22333333  
        //       AByte    BByte    CByte
        //
        // where: 
        //
        //      000000 is the first 6-bit word, 111111 is the second, and so on.
    u8 AByte;
    u8 BByte;
    u8 CByte;
        // AByte, BByte, and CByte are single-byte buffers used in the process 
        // of packing 6-bit words into bytes.
        //
    u8 LastSymbolRead;
        // While reading base64 files, this value is used to keep track of the
        // last letter from the base64 alphabet that was read from the file.
        // This is needed for properly ending the stream when padding ('=')
        // characters are used.
} FILEX;  
 
//------------------------------------------------------------------------------
                          
#define MAX_PARAMETER_TAG_SIZE    (32)
    // Maximum size of a command line parameter tag such as '-keyfile', in bytes.
    
#define MAX_PARAMETER_VALUE_SIZE  (2000)
    // Maximum size of a command line parameter value string, in bytes.
    // In the following example, '143.key' is the parameter value:
    //
    //                      -keyfile 143.key
    //
    // This sets the limit on the maximum size of a password parameter.
 
//------------------------------------------------------------------------------
// RESULT CODES
//------------------------------------------------------------------------------
 
int Result;
    // Result code returned when the application exits, one of the following
    // values. Applications calling the ot7 command line tool can use these
    // result codes in error handling routines.
    //
    // Zero is reserved to mean successful completion. Error numbers start at 
    // 700 for compatibility with applications that use error codes assigned to 
    // small numbers. If calling applications see an error code in the 700 
    // range, then that's a hint that the error code was produced by ot7.
 
#define RESULT_OK 0 
            // Use 0 for no error result for compatibility with other
            // applications.
                 
#define RESULT_CANT_CLOSE_ENCRYPTED_FILE               700
#define RESULT_CANT_CLOSE_FILE                         701
#define RESULT_CANT_CLOSE_KEY_FILE                     702
#define RESULT_CANT_CLOSE_PLAINTEXT_FILE               703
#define RESULT_CANT_IDENTIFY_KEYADDRESS_FOR_DECRYPTION 704
#define RESULT_CANT_IDENTIFY_KEYID_FOR_DECRYPTION      705
#define RESULT_CANT_IDENTIFY_KEYID_FOR_ENCRYPTION      706
#define RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING    707
#define RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_WRITING    708
#define RESULT_CANT_OPEN_FILE_FOR_WRITING              709
#define RESULT_CANT_OPEN_KEY_FILE_FOR_READING          710
#define RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING          711
#define RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_READING    712
#define RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_WRITING    713
#define RESULT_CANT_READ_ENCRYPTED_FILE                714
#define RESULT_CANT_READ_KEY_FILE                      715
#define RESULT_CANT_READ_KEY_MAP_FILE                  716
#define RESULT_CANT_READ_PLAINTEXT_FILE                717
#define RESULT_CANT_SEEK_IN_ENCRYPTED_FILE             718
#define RESULT_CANT_SEEK_IN_KEY_FILE                   719
#define RESULT_CANT_SEEK_IN_PLAINTEXT_FILE             720
#define RESULT_CANT_WRITE_ENCRYPTED_FILE               721
#define RESULT_CANT_WRITE_FILE                         722
#define RESULT_CANT_WRITE_KEY_FILE                     723
#define RESULT_CANT_WRITE_PLAINTEXT_FILE               724
#define RESULT_CANT_ERASE_USED_KEY_BYTES               725
#define RESULT_INVALID_CHECKSUM_DECRYPTED              726
#define RESULT_INVALID_COMMAND_LINE_PARAMETER          727
#define RESULT_INVALID_COMPUTED_HEADER_KEY             728
#define RESULT_INVALID_DECRYPTION_OUTPUT               729
#define RESULT_INVALID_ENCRYPTED_FILE_FORMAT           730
#define RESULT_INVALID_KEY_FILE_NAME                   731
#define RESULT_INVALID_KEY_FILE_POINTER                732
#define RESULT_INVALID_KEY_MAP_FILE_NAME               733
#define RESULT_INVALID_LOG_FILE_NAME                   734
#define RESULT_INVALID_NAME_OF_FILE_TO_DECRYPT         735
#define RESULT_INVALID_NAME_OF_PLAINTEXT_FILE          736
#define RESULT_INVALID_OUTPUT_FILE_NAME                737
#define RESULT_KEY_FILE_IS_TOO_SMALL                   738
#define RESULT_MISSING_COMMAND_LINE_PARAMETER          739
#define RESULT_MISSING_KEYID_IN_KEYDEF_STRING          740
#define RESULT_NO_COMMAND_LINE_PARAMETERS_GIVEN        741
#define RESULT_OUT_OF_MEMORY                           742
#define RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD          743
#define RESULT_SKEIN_TEST_FINAL_RESULT_IS_INVALID      744
#define RESULT_SKEIN_TEST_INITIALIZATION_FAILED        745
#define RESULT_TEXT_LINE_TOO_LONG_FOR_BUFFER           746
     
//------------------------------------------------------------------------------
 
#define OT7_VERSION_STRING "OT7 -- One-Time Pad Encryption Tool v6"
            // Version identifier for this application.

// This usage info is printed to standard output for the '-h' command. 
// This is a zero-terminated array of strings.
s8*
Help[] =
{
"This tool encrypts and decrypts files using one-time pad encryption.",
"--------------------------------------------------------------------------------",
"",
"U S A G E   I N F O:",
"",
"General command format:",
"",
"                            ot7 < parameter list >",
"Parameters:",
"",
"    -binary",
"        Select binary encoding for the encrypted file. The default encoding is",
"        base64, a convenient form for email messages.",
"",
"    -d [<file name>]",    
"        Decrypt the specified file. If the file name is not specified, then",
"        the default file 'ot7d.in' will be used and the '-d' tag must be the",
"        last item on the command line.",
"",
"    -e [<file name>]",
"        Encrypt the specified file. If the file name is not specified, then",
"        the default file 'plain.txt' will be used and the '-e' tag must be",
"        the last item on the command line.",
"",
"    -erasekey",
"        Erase key bytes in the key file after they have been used for",
"        encryption or decryption. This provides forward security for encrypted",
"        messages. The default is to not delete key bytes.",
"",
"    -f <# of bytes>",
"        Number of extra fill bytes to use for masking the size of the",
"        plaintext, eg. -f 1024. The default number of fill bytes is a random",
"        number ranging from 0 to the size of the plaintext.",
"",
"    -h or -help",
"        Prints this usage info.",
"",
"    -ID <identifier>",
"        Specify an identifier used to look up a key definition in a key map",
"        file. This is an optional way to select a key file during encryption.",
"        Associating an identifier with a key definition provides an easy to",
"        remember way of selecting a key for encryption.",
"",
"    -keyfile <file name>",
"        Specify a key file to be used for encryption or decryption. This can be",
"        any file containing truly random bytes.",
"",
"    -KeyID <number>",  
"        Specify the KeyID value used to generate the header of a file being",
"        encrypted.",
"",
"        A KeyID number is the primary identifier of a key definition.",
"",
"        KeyID numbers can be expressed in decimal or in hexadecimal form, eg.",
"        '-KeyID 0x41ad9' or '-KeyID 8189'. Values can range from 0 to the",
"        largest number that can be stored in a 64-bit field,",
"        18446744073709551616.",
"",
"    -keymap <file name>",
"        Specify the name of the file to use for looking up a key definition.",
"        If this parameter is not used, then the default key map file name is", 
"        'key.map'. It is convenient to use a key map file, but this command",
"        line tool also works without a key map file.",
"",
"    -nofilename",
"        Disable filename inclusion in OT7 records during encryption. Using this",
"        option will save space in the OT7 record and make the name of the",
"        decrypted file dependant on a parameter set at decryption time. See the",
"        -od option for how to specify the name of the decrypted output file.",
"",
"    -od <file name>",
"        Specify the output file name for decryption - optional. This defaults to",
"        the file name embedded in the OT7 file or to 'ot7d.out' if there is no",
"        embedded filename.", 
"",
"    -oe <file name>",
"        Specify the output file name for encryption. The default file name is",
"        'ot7e.out' if this parameter is not used.", 
"", 
"    -p <password string>",
"        A password can be used for an extra layer of security. The same",
"        password used for encrypting a file will be needed to decrypt it.",
"        Passwords are either a single word or a phrase enclosed in double",
"        quotes, and can be up to 2000 characters long.",
"",
"        If no password is specified on the command line, then the password",
"        specified in a key definition is used. If no password is specified",
"        in a key definition, then the default password compiled into the ot7",
"        command line tool is used.",
"",
"    -silent",
"        Disable verbose mode to stop printing status messages.",
"",
"    -testhash",
"        Test the Skein hash functions to make sure they are working properly.",
"        After compiling the OT7 application, run this test as a normal part",
"        of the validation process. A passing test means that OT7's hash",
"        routines conform to the standard Skein algorithm.",
"",
"    -u or -unused",
"        Print the the number of available key bytes in a specified key file.",
"        Key bytes are used only once, so encryption reduces the available key",
"        bytes.",
"",
"    -v", 
"        Enable verbose mode to print status messages.",
"",
"--------------------------------------------------------------------------------",
"",
"The following examples are how to use ot7 without a 'key.map' configuration",
"file.",
"",
"Encryption examples:",
"",
"    ot7 -e note.txt -oe note.b64 -KeyID 143 -keyfile 143.key",
"    ot7 -e note.txt -oe note.b64 -KeyID 143 -keyfile 143.key -p \"my password\"",
"    ot7 -e note.txt -oe note.bin -KeyID 143 -keyfile 143.key -binary",
"",
"Decryption examples:",
"",
"    ot7 -d note.b64 -KeyID 143 -keyfile 143.key",
"    ot7 -d note.b64 -KeyID 143 -keyfile 143.key -p \"my password\"",
"    ot7 -d note.b64 -KeyID 143 -keyfile 143.key -erasekey",
"    ot7 -d note.b64 -KeyID 143 -keyfile 143.key -od note.txt",
"",           
"To print the number of available key bytes in a key file:",
"",
"    ot7 -unused -keyfile 143.key",
"",
"--------------------------------------------------------------------------------",
"",
"A 'key.map' configuration file can be used to simplify the use of ot7.",
"",
"With a 'key.map' file like the one listed below, it becomes possible to encrypt",
"and decrypt a file named 'myfile.zip' as follows:",
"",
"Encrypting: ot7 -e myfile.zip -oe myfile.ot7 -ID general",
"",
"Decrypting: ot7 -d myfile.ot7",
"",
"Here's an example of how to encrypt an email message for Dan Jones in several",
"different ways:",
"",
"    ot7 -e email.txt -KeyID 143",
"    ot7 -e email.txt -ID \"Dan Jones\"",
"    ot7 -e email.txt -ID danjones@privatemail.net",
"    ot7 -e email.txt -ID BM-GtkZoid3xpT4nwxezDfpWtYAfY6vgyHd",
"    ot7 -e email.txt -ID \"Dan Jones\" -p \"a special password for today\"",
"",
"All of the above commands will encrypt the file 'email.txt' to produce an", 
"encrypted file named 'Dan.txt'.",  
"",
"If Dan Jones has a key definition for KeyID( 143 ), then he can decrypt", 
"'Dan.txt' using one of these two command lines:",
"",
"    ot7 -d Dan.txt",
"",
"    ot7 -d Dan.txt -p \"a special password for today\"", 
"",
"... resulting in the file 'email.txt' being produced in his current", 
"directory.", 
"",
"--------------------------------------------------------------------------------",
"KEY.MAP FILE FORMAT - How to make a configuration file.",
"--------------------------------------------------------------------------------",
"",
"'key.map' files are another source of input for the ot7 command line tool.",
"",
"A 'key.map' file provides configuration information.",
"",
"It's called a key map because it tells where the key files are located and also",
"how KeyID numbers map to one-time pad key files.",
"",
"A 'key.map' file is composed of one or more key definitions. Each key definition", 
"organizes the information needed to use one-time pad key files for a particular", 
"purpose.",
"",
"It may be convenient to store frequently used parameter settings as part of a", 
"key definition in a 'key.map' file instead of typing them on the command line.",
"",
"Here is an example 'key.map' file that you can use as a template for your own:",
"",
"//==============================================================================",
"//======================= BEGIN KEY.MAP FILE CONTENTS ==========================",
"//==============================================================================",
"",
"//<---- 'key.map' files may contain comments which begin with '//' and continue",  
"//      to the end of the line.",
"//",
"// A 'key.map' file may contain one or more key definitions.",
"//",
"// A key definition has this form:",
"//",
"//    KeyID( 143 )",
"//    {",
"//          ...the parameters of the key...",
"//    }",
"//",
"// where:",
"//",
"//    '143' is the KeyID number of the key definition, the primary identifier", 
"//          of the definition. KeyID numbers must be unique within the", 
"//          'key.map' file in which they are used.",
"//",
"//    KeyID numbers can be expressed in decimal or in hexadecimal form, eg.", 
"//    '-KeyID 0x41ad9' or '-KeyID 8189'. Values can range from 0 to the largest",
"//    number that can be stored in a 64-bit field, 18446744073709551616.",
"//",
"//    The KeyID is used to make the KeyIDHash stored in the header of an OT7", 
"//    record.", 
"//",
"//    When an OT7 record is decrypted, the KeyIDHash in the OT7 record header",  
"//    implies which key definition to used for decryption. This lookup procedure", 
"//    can be overridden by specifying that a certain KeyID be used instead with", 
"//    the '-KeyID <number>' command line option.",
"//",
"//    The parameters of a key definition follows a consistent format:",
"//",
"//        Each parameter is listed on a separate line.",
"//",
"//        Each parameter begins with a parameter tag that starts with '-', for",  
"//        example '-keyfile' or '-ID'.",
"//",
"//        One or more spaces separate the parameter tag from any data that",
"//        follows. Multi-word parameter values are enclosed in quotes.",
"",
"// Here is an example key definition:",
"",
"KeyID( 143 )",
"{",
"    //--------------------------------------------------------------------------",
"    // K E Y   F I L E S",
"    //--------------------------------------------------------------------------",
"",
"    // A key definition refers to a pool of one or more one-time pad key files,",
"    // each one listed on a separate line with the parameter tag '-keyfile'.",
"",
"    // This is the pool of key files for this key definition:",
"",
"    -keyfile file1.key",
"    -keyfile /home/myfiles/file2.key",
"    -keyfile some_other_file.bin",
"    -keyfile any_other_filename.zip",
"    -keyfile \"a file name with spaces.key\"",
"",
"    // Each key file contains truly random bytes that are only used once.", 
"    //",
"    // Key files need to be writable only if key bytes are erased after use by", 
"    // selecting the '-erasekey' option. Otherwise, key files may be read-only.",
"    //",
"    // To complete a key definition, it is sufficient to define just one key",
"    // file. If several key files are used, then the ordering of the files in", 
"    // the key definition determines the order in which they are used for",
"    // encryption and decryption.",
"    //",
"    // A decryptor uses the KeyID number to look up a particular key definition.", 
"    // If that key definition contains multiple key files, then it may be", 
"    // necessary to try to decrypt using several different key files before the", 
"    // right one is found to successfully decrypt the message. The decryption", 
"    // routine automatically handles this search process, but it will be slower", 
"    // than using just one key file per key definition.",
"",
"    //--------------------------------------------------------------------------",
"    // P A S S W O R D",
"    //--------------------------------------------------------------------------",
"",
"    // Passwords provide an extra layer of security in addition to that provided", 
"    // by one-time pad key files. When a password is used to encrypt a file,", 
"    // then the same password must be used to decrypt the file.",
"    //",
"    // Passwords can be stored in key definitions or entered on the command",
"    // line. If a password is entered on the command line, then it overrides", 
"    // any password that might also be stored in a key definition. In this", 
"    // example, a password is stored in the key definition.",
"",
"    -p \"This is the password for encrypting files sent to Dan Jones.\"",
"",
"    // Passwords are either single words or phrases enclosed in double quotes",
"    // Passwords may be up to 2000 characters long. Longer passwords are more", 
"    // secure than shorter ones.",
"    //",
"    // If no password is specified by the user, then the default password",
"    // compiled into the OT7 application is used. See DefaultPassword for where",
"    // that is defined.",
"",
"    //--------------------------------------------------------------------------",
"    // O T H E R   O P T I O N S",
"    //--------------------------------------------------------------------------",
"",
"    // For convenience, other command line options can be stored with a key", 
"    // definition. This extra information will automatically be presented to the", 
"    // command line parser each time the key is used during encryption or", 
"    // decryption. This allows an encryption policy to be set up once and then", 
"    // used simply by referring to the key definition with either the '-KeyID'", 
"    // or '-ID' command line options.",
"    //",
"    // Secondary identifiers can optionally be associated with a key definition", 
"    // to give another way to refer to a key definition. List each identifier", 
"    // on a separate line with the parameter tag '-ID'. Any string can be used", 
"    // as an identifier. A phrase can be used as an identifier by enclosing it",
"    // in double quotes, as shown below.",
"",
"    -ID \"Dan Jones\"",
"    -ID danjones@privatemail.net",
"    -ID BM-GtkZoid3xpT4nwxezDfpWtYAfY6vgyHd",
"",
"    // Use the '-erasekey' option if you want to erase key bytes after use.",
"    // -erasekey",
"",
"    // Use the '-v' option to enable verbose mode which prints status",
"    // messages.",
"    -v",
"",
"    // Use the '-oe' option to name the default output file used when encrypting",
"    // files. In this example, encrypted files are written to 'Dan.txt'. If the", 
"    // '-oe' option is included on the command line, it will override this", 
"    // default setting.",
"    -oe Dan.txt",
"",
"} // End of the key definition for KeyID 143.",
"",
"// There can be any number of definitions in a 'key.map' file.",
"",
"// Here is another definition to be used for general purpose encryption.",
"KeyID( 7891 )",  
"{",
"    -keyfile general.key",
"    -ID general",
"    -p \"password for general purpose encryption\"",
"}",
"",
"//==============================================================================",
"//======================== END KEY.MAP FILE CONTENTS ===========================",
"//==============================================================================",
"",

    // This 0 marks the end of this list of strings.
    0    
};

// base64 lookup table for converting 6-bit words into ASCII. From RFC4648.
s8
base64Alphabet[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

#define BASE64_PAD_CHAR '='
            // Character to use for padding the end of a base64 sequence 
            // to make it an integral number of 24-bit groups.

// Test for whether a byte is in the base64 alphabet.              
#define IsBase64(a)   ( ( (a) >= 'A' && (a) <= 'Z' ) || \
                        ( (a) >= 'a' && (a) <= 'z' ) || \
                        ( (a) >= '0' && (a) <= '9' ) || \
                        ( (a) == '+' ) || \
                        ( (a) == '/' ) || \
                        ( (a) == '=' ) )
            
#define BASE64_LINE_LENGTH 76
            // Number of base64 characters to write on a line before 
            // inserting a CRLF end-of-line sequence. 76 is the RFC 2045 line 
            // length limit.

// Convert a 4-bit word to an ASCII hex value using this lookup table.
u8  HexDigit[] = { '0','1','2','3','4','5','6','7',
                   '8','9','A','B','C','D','E','F' };

// Convert an ASCII hex value to a 4-bit word using this lookup table.
//
// Subtract '0' from an ASCII hex digit and then use the result as an index 
// into this table to convert an ASCII hex digit to binary, like this:
//
//     b = HexDigitToBinary[ h - '0' ];
u8
HexDigitToBinary[] =
{    
// '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7' // <-- ASCII, based at '0'.
    0,   1,   2,   3,   4,   5,   6,   7, // <-- 4-bit word value.

// '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
    8,   9,   0,   0,   0,   0,   0,   0,   

// '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'
    0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,   0, 

// 'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    0,   0,   0,   0,   0,   0,   0,   0,
    
// 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'
    0,   0,   0,   0,   0,   0,   0,   0,  
    
// 'X'  'Y'  'Z'  '['  '\'  ']'  '^'  '_'
    0,   0,   0,   0,   0,   0,   0,   0,
    
// '`'  'a'  'b'  'c'  'd'  'e'  'f'
    0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

//------------------------------------------------------------------------------
// SKEIN1024 HASH FUNCTION - VERSION 1.3
//------------------------------------------------------------------------------
/* tweak word T[1]: bit field starting positions */
#define SKEIN_T1_BIT(BIT)       ((BIT) - 64)            /* offset 64 because it's the second word  */
                                
#define SKEIN_T1_POS_TREE_LVL   SKEIN_T1_BIT(112)       /* bits 112..118: level in hash tree       */
#define SKEIN_T1_POS_BIT_PAD    SKEIN_T1_BIT(119)       /* bit  119     : partial final input byte */
#define SKEIN_T1_POS_BLK_TYPE   SKEIN_T1_BIT(120)       /* bits 120..125: type field               */
#define SKEIN_T1_POS_FIRST      SKEIN_T1_BIT(126)       /* bits 126     : first block flag         */
#define SKEIN_T1_POS_FINAL      SKEIN_T1_BIT(127)       /* bit  127     : final block flag         */
                                
/* tweak word T[1]: flag bit definition(s) */
#define SKEIN_T1_FLAG_FIRST     (((u64)  1 ) << SKEIN_T1_POS_FIRST)
#define SKEIN_T1_FLAG_FINAL     (((u64)  1 ) << SKEIN_T1_POS_FINAL)
#define SKEIN_T1_FLAG_BIT_PAD   (((u64)  1 ) << SKEIN_T1_POS_BIT_PAD)
                                
/* tweak word T[1]: tree level bit field mask */
#define SKEIN_T1_TREE_LVL_MASK  (((u64)0x7F) << SKEIN_T1_POS_TREE_LVL)
#define SKEIN_T1_TREE_LEVEL(n)  (((u64) (n)) << SKEIN_T1_POS_TREE_LVL)

/* tweak word T[1]: block type field */
#define SKEIN_BLK_TYPE_KEY      ( 0)                    /* key, for MAC and KDF */
#define SKEIN_BLK_TYPE_CFG      ( 4)                    /* configuration block */
#define SKEIN_BLK_TYPE_PERS     ( 8)                    /* personalization string */
#define SKEIN_BLK_TYPE_PK       (12)                    /* public key (for digital signature hashing) */
#define SKEIN_BLK_TYPE_KDF      (16)                    /* key identifier for KDF */
#define SKEIN_BLK_TYPE_NONCE    (20)                    /* nonce for PRNG */
#define SKEIN_BLK_TYPE_MSG      (48)                    /* message processing */
#define SKEIN_BLK_TYPE_OUT      (63)                    /* output stage */
#define SKEIN_BLK_TYPE_MASK     (63)                    /* bit field mask */

#define SKEIN_T1_BLK_TYPE(T)   (((u64) (SKEIN_BLK_TYPE_##T)) << SKEIN_T1_POS_BLK_TYPE)
#define SKEIN_T1_BLK_TYPE_KEY   SKEIN_T1_BLK_TYPE(KEY)  /* key, for MAC and KDF */
#define SKEIN_T1_BLK_TYPE_CFG   SKEIN_T1_BLK_TYPE(CFG)  /* configuration block */
#define SKEIN_T1_BLK_TYPE_PERS  SKEIN_T1_BLK_TYPE(PERS) /* personalization string */
#define SKEIN_T1_BLK_TYPE_PK    SKEIN_T1_BLK_TYPE(PK)   /* public key (for digital signature hashing) */
#define SKEIN_T1_BLK_TYPE_KDF   SKEIN_T1_BLK_TYPE(KDF)  /* key identifier for KDF */
#define SKEIN_T1_BLK_TYPE_NONCE SKEIN_T1_BLK_TYPE(NONCE)/* nonce for PRNG */
#define SKEIN_T1_BLK_TYPE_MSG   SKEIN_T1_BLK_TYPE(MSG)  /* message processing */
#define SKEIN_T1_BLK_TYPE_OUT   SKEIN_T1_BLK_TYPE(OUT)  /* output stage */
#define SKEIN_T1_BLK_TYPE_MASK  SKEIN_T1_BLK_TYPE(MASK) /* field bit mask */

#define SKEIN_T1_BLK_TYPE_CFG_FINAL       (SKEIN_T1_BLK_TYPE_CFG | SKEIN_T1_FLAG_FINAL)
#define SKEIN_T1_BLK_TYPE_OUT_FINAL       (SKEIN_T1_BLK_TYPE_OUT | SKEIN_T1_FLAG_FINAL)

#define SKEIN_VERSION           (1)

#ifndef SKEIN_ID_STRING_LE      /* allow compile-time personalization */
#define SKEIN_ID_STRING_LE      (0x33414853)            /* "SHA3" (little-endian)*/
#endif

enum    
{   
    // Skein1024 round rotation constants from "Table 4: Rotation constants 
    // R(d,j) for each Nw" of skein1.3.pdf.
    R_0_0=24, R_0_1=13, R_0_2= 8, R_0_3=47, R_0_4= 8, R_0_5=17, R_0_6=22, R_0_7=37,
    R_1_0=38, R_1_1=19, R_1_2=10, R_1_3=55, R_1_4=49, R_1_5=18, R_1_6=23, R_1_7=52,
    R_2_0=33, R_2_1= 4, R_2_2=51, R_2_3=13, R_2_4=34, R_2_5=41, R_2_6=59, R_2_7=17,
    R_3_0= 5, R_3_1=20, R_3_2=48, R_3_3=41, R_3_4=47, R_3_5=28, R_3_6=16, R_3_7=25,
    R_4_0=41, R_4_1= 9, R_4_2=37, R_4_3=31, R_4_4=12, R_4_5=47, R_4_6=44, R_4_7=30,
    R_5_0=16, R_5_1=34, R_5_2=56, R_5_3=51, R_5_4= 4, R_5_5=53, R_5_6=42, R_5_7=41,
    R_6_0=31, R_6_1=44, R_6_2=47, R_6_3=46, R_6_4=19, R_6_5=42, R_6_6=44, R_6_7=25,
    R_7_0= 9, R_7_1=48, R_7_2=35, R_7_3=52, R_7_4=23, R_7_5=31, R_7_6=37, R_7_7=20
};

#define SKEIN_MK_64(hi32,lo32)  ((lo32) + (((u64) (hi32)) << 32))
#define SKEIN_SCHEMA_VER        SKEIN_MK_64(SKEIN_VERSION,SKEIN_ID_STRING_LE)
#define SKEIN_KS_PARITY         SKEIN_MK_64(0x1BD11BDA,0xA9FC1A22)

#define  SKEIN_MODIFIER_WORDS  (2)  // Number of modifier (tweak) words.
#define SKEIN1024_STATE_WORDS  (16)
#define SKEIN1024_BLOCK_BYTES  (8*SKEIN1024_STATE_WORDS)
 
// 1024-bit Skein hash context structure.
typedef struct                            
{
    u32 hashBitLen;                // Size of hash result, in bits.
    u32 bCnt;                      // Current byte count in buffer b[].
    u64 T[SKEIN_MODIFIER_WORDS];   // Tweak words: T[0]=byte cnt, T[1]=flags.
    u64 X[SKEIN1024_STATE_WORDS];  // Chaining variables.
    u8  b[SKEIN1024_BLOCK_BYTES];  // Partial block buffer (8-byte aligned).
} Skein1024Context;

#define SKEIN1024_ROUNDS_TOTAL (80)

#define RotL_64(x,N)    (((x) << (N)) | ((x) >> (64-(N))))

#define SKEIN_CFG_STR_LEN       (4*8)

// bit field definitions in config block treeInfo word.
#define SKEIN_CFG_TREE_LEAF_SIZE_POS  ( 0)
#define SKEIN_CFG_TREE_NODE_SIZE_POS  ( 8)
#define SKEIN_CFG_TREE_MAX_LEVEL_POS  (16)

#define SKEIN_CFG_TREE_LEAF_SIZE_MSK  (((u64) 0xFF) << SKEIN_CFG_TREE_LEAF_SIZE_POS)
#define SKEIN_CFG_TREE_NODE_SIZE_MSK  (((u64) 0xFF) << SKEIN_CFG_TREE_NODE_SIZE_POS)
#define SKEIN_CFG_TREE_MAX_LEVEL_MSK  (((u64) 0xFF) << SKEIN_CFG_TREE_MAX_LEVEL_POS)

#define SKEIN_CFG_TREE_INFO(leaf,node,maxLvl)                \
    ( (((u64)(leaf  )) << SKEIN_CFG_TREE_LEAF_SIZE_POS) |    \
      (((u64)(node  )) << SKEIN_CFG_TREE_NODE_SIZE_POS) |    \
      (((u64)(maxLvl)) << SKEIN_CFG_TREE_MAX_LEVEL_POS) )

#define SKEIN_CFG_TREE_INFO_SEQUENTIAL SKEIN_CFG_TREE_INFO(0,0,0) 
        // Use as treeInfo in InitExt() call for sequential processing.

//   Skein macros for getting/setting tweak words, etc.
//   These are useful for partial input bytes, hash tree init/update, etc.
#define Skein_Get_Tweak(ctxPtr,TWK_NUM)         ((ctxPtr)->T[TWK_NUM])
#define Skein_Set_Tweak(ctxPtr,TWK_NUM,tVal)    {(ctxPtr)->T[TWK_NUM] = (tVal);}
#define Skein_Set_T0(ctxPtr,T0) Skein_Set_Tweak(ctxPtr,0,T0)
#define Skein_Set_T1(ctxPtr,T1) Skein_Set_Tweak(ctxPtr,1,T1)

// Set both tweak words at once.
#define Skein_Set_T0_T1(ctxPtr,T0,T1)           \
    {                                           \
    Skein_Set_T0(ctxPtr,(T0));                  \
    Skein_Set_T1(ctxPtr,(T1));                  \
    }

// set up for starting with a new type: h.T[0]=0; h.T[1] = NEW_TYPE; h.bCnt=0; 
#define Skein_Start_New_Type(ctxPtr,BLK_TYPE)   \
    { Skein_Set_T0_T1(ctxPtr,0,SKEIN_T1_FLAG_FIRST | BLK_TYPE); (ctxPtr)->bCnt=0; }

// Macro to perform a key injection.
#define InjectKey(r)                                       \
    for (i=0;i < SKEIN1024_STATE_WORDS;i++)                \
         X[i] += ks[((r)+i) % (SKEIN1024_STATE_WORDS+1)];  \
    X[SKEIN1024_STATE_WORDS-3] += ts[((r)+0) % 3];         \
    X[SKEIN1024_STATE_WORDS-2] += ts[((r)+1) % 3];         \
    X[SKEIN1024_STATE_WORDS-1] += (r);                

// Skein-1024-1024 Test Vector Data
//
// From Skein reference document "The Skein Hash Function Family, Version 1.3 - 
// 1 Oct 2010" (skein1.3.pdf), Appendix B Initial Chaining Values, B.13 page 72. 
u64 
Skein_1024_1024_Initial_Chaining_Values[] =
{
0xD593DA0741E72355LL, 0x15B5E511AC73E00CLL, 0x5180E5AEBAF2C4F0LL, 0x03BD41D3FCBCAFAFLL, 
0x1CAEC6FD1983A898LL, 0x6E510B8BCDD0589FLL, 0x77E2BDFDC6394ADALL, 0xC11E1DB524DCB0A3LL, 
0xD6D14AF9C6329AB5LL, 0x6A9B0BFC6EB67E0DLL, 0x9243C60DCCFF1332LL, 0x1A1F1DDE743F02D4LL, 
0x0996753C10ED0BB8LL, 0x6572DD22F2B4969ALL, 0x61FD3062D00A579ALL, 0x1DE0536E8682E539LL 
};

// From Skein reference document "The Skein Hash Function Family, Version 1.3 - 
// 1 Oct 2010" (skein1.3.pdf), Appendix C Test Vectors, C.3 page 74. 
u8
Skein_1024_1024_Test_Vector_1_Message_Data[] =
{
    0xFF
};

u8
Skein_1024_1024_Test_Vector_1_Result[] =
{
    0xE6, 0x2C, 0x05, 0x80, 0x2E, 0xA0, 0x15, 0x24, 
    0x07, 0xCD, 0xD8, 0x78, 0x7F, 0xDA, 0x9E, 0x35, 
    0x70, 0x3D, 0xE8, 0x62, 0xA4, 0xFB, 0xC1, 0x19,
    0xCF, 0xF8, 0x59, 0x0A, 0xFE, 0x79, 0x25, 0x0B, 
    0xCC, 0xC8, 0xB3, 0xFA, 0xF1, 0xBD, 0x24, 0x22,
    0xAB, 0x5C, 0x0D, 0x26, 0x3F, 0xB2, 0xF8, 0xAF, 
    0xB3, 0xF7, 0x96, 0xF0, 0x48, 0x00, 0x03, 0x81,
    0x53, 0x1B, 0x6F, 0x00, 0xD8, 0x51, 0x61, 0xBC, 
    0x0F, 0xFF, 0x4B, 0xEF, 0x24, 0x86, 0xB1, 0xEB,
    0xCD, 0x37, 0x73, 0xFA, 0xBF, 0x50, 0xAD, 0x4A, 
    0xD5, 0x63, 0x9A, 0xF9, 0x04, 0x0E, 0x3F, 0x29,
    0xC6, 0xC9, 0x31, 0x30, 0x1B, 0xF7, 0x98, 0x32, 
    0xE9, 0xDA, 0x09, 0x85, 0x7E, 0x83, 0x1E, 0x82,
    0xEF, 0x8B, 0x46, 0x91, 0xC2, 0x35, 0x65, 0x65, 
    0x15, 0xD4, 0x37, 0xD2, 0xBD, 0xA3, 0x3B, 0xCE,
    0xC0, 0x01, 0xC6, 0x7F, 0xFD, 0xE1, 0x5B, 0xA8
};

// From Skein reference document "The Skein Hash Function Family, Version 1.3 - 
// 1 Oct 2010" (skein1.3.pdf), Appendix C Test Vectors, C.3 pages 74-75. 
u8
Skein_1024_1024_Test_Vector_2_Message_Data[] =
{
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 
    0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 
    0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
    0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0, 
    0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
    0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0, 
    0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
    0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0, 
    0xBF, 0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8,
    0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1, 0xB0, 
    0xAF, 0xAE, 0xAD, 0xAC, 0xAB, 0xAA, 0xA9, 0xA8,
    0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0,
    0x9F, 0x9E, 0x9D, 0x9C, 0x9B, 0x9A, 0x99, 0x98,
    0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 
    0x8F, 0x8E, 0x8D, 0x8C, 0x8B, 0x8A, 0x89, 0x88,
    0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80   
};

u8
Skein_1024_1024_Test_Vector_2_Result[] =
{
    0x1F, 0x3E, 0x02, 0xC4, 0x6F, 0xB8, 0x0A, 0x3F,
    0xCD, 0x2D, 0xFB, 0xBC, 0x7C, 0x17, 0x38, 0x00, 
    0xB4, 0x0C, 0x60, 0xC2, 0x35, 0x4A, 0xF5, 0x51,
    0x18, 0x9E, 0xBF, 0x43, 0x3C, 0x3D, 0x85, 0xF9, 
    0xFF, 0x18, 0x03, 0xE6, 0xD9, 0x20, 0x49, 0x31,
    0x79, 0xED, 0x7A, 0xE7, 0xFC, 0xE6, 0x9C, 0x35, 
    0x81, 0xA5, 0xA2, 0xF8, 0x2D, 0x3E, 0x0C, 0x7A,
    0x29, 0x55, 0x74, 0xD0, 0xCD, 0x7D, 0x21, 0x7C, 
    0x48, 0x4D, 0x2F, 0x63, 0x13, 0xD5, 0x9A, 0x77,
    0x18, 0xEA, 0xD0, 0x7D, 0x07, 0x29, 0xC2, 0x48, 
    0x51, 0xD7, 0xE7, 0xD2, 0x49, 0x1B, 0x90, 0x2D,
    0x48, 0x91, 0x94, 0xE6, 0xB7, 0xD3, 0x69, 0xDB, 
    0x0A, 0xB7, 0xAA, 0x10, 0x6F, 0x0E, 0xE0, 0xA3,
    0x9A, 0x42, 0xEF, 0xC5, 0x4F, 0x18, 0xD9, 0x37,
    0x76, 0x08, 0x09, 0x85, 0xF9, 0x07, 0x57, 0x4F,
    0x99, 0x5E, 0xC6, 0xA3, 0x71, 0x53, 0xA5, 0x78
};

// From Skein reference document "The Skein Hash Function Family, Version 1.3 - 
// 1 Oct 2010" (skein1.3.pdf), Appendix C Test Vectors, C.3 page 75. 
u8
Skein_1024_1024_Test_Vector_3_Message_Data[] =
{
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
    0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 
    0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
    0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0, 
    0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
    0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0, 
    0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
    0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0, 
    0xBF, 0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8,
    0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1, 0xB0, 
    0xAF, 0xAE, 0xAD, 0xAC, 0xAB, 0xAA, 0xA9, 0xA8,
    0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0, 
    0x9F, 0x9E, 0x9D, 0x9C, 0x9B, 0x9A, 0x99, 0x98,
    0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 
    0x8F, 0x8E, 0x8D, 0x8C, 0x8B, 0x8A, 0x89, 0x88,
    0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80, 
    0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x7A, 0x79, 0x78,
    0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70, 
    0x6F, 0x6E, 0x6D, 0x6C, 0x6B, 0x6A, 0x69, 0x68,
    0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 
    0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58,
    0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 
    0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48,
    0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 
    0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38,
    0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 
    0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28,
    0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 
    0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
    0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 
};

u8
Skein_1024_1024_Test_Vector_3_Result[] =
{
    0x84, 0x2A, 0x53, 0xC9, 0x9C, 0x12, 0xB0, 0xCF,
    0x80, 0xCF, 0x69, 0x49, 0x1B, 0xE5, 0xE2, 0xF7, 
    0x51, 0x5D, 0xE8, 0x73, 0x3B, 0x6E, 0xA9, 0x42,
    0x2D, 0xFD, 0x67, 0x66, 0x65, 0xB5, 0xFA, 0x42, 
    0xFF, 0xB3, 0xA9, 0xC4, 0x8C, 0x21, 0x77, 0x77,
    0x95, 0x08, 0x48, 0xCE, 0xCD, 0xB4, 0x8F, 0x64, 
    0x0F, 0x81, 0xFB, 0x92, 0xBE, 0xF6, 0xF8, 0x8F,
    0x7A, 0x85, 0xC1, 0xF7, 0xCD, 0x14, 0x46, 0xC9, 
    0x16, 0x1C, 0x0A, 0xFE, 0x8F, 0x25, 0xAE, 0x44,
    0x4F, 0x40, 0xD3, 0x68, 0x00, 0x81, 0xC3, 0x5A, 
    0xA4, 0x3F, 0x64, 0x0F, 0xD5, 0xFA, 0x3C, 0x3C,
    0x03, 0x0B, 0xCC, 0x06, 0xAB, 0xAC, 0x01, 0xD0, 
    0x98, 0xBC, 0xC9, 0x84, 0xEB, 0xD8, 0x32, 0x27,
    0x12, 0x92, 0x1E, 0x00, 0xB1, 0xBA, 0x07, 0xD6, 
    0xD0, 0x1F, 0x26, 0x90, 0x70, 0x50, 0x25, 0x5E,
    0xF2, 0xC8, 0xE2, 0x4F, 0x71, 0x6C, 0x52, 0xA5 
};

//------------------------------------------------------------------------------

#define HEADERKEY_BIT_COUNT    (64)
    // Size of the HeaderKey field in bits, the first field of an OT7 record.

#define HEADERKEY_BYTE_COUNT   (8)
    // Size of the HeaderKey field in bytes.
    
//------------------------------------------------------------------------------

#define KEYIDHASH128BIT_BIT_COUNT  (128)
    // Size of the 128-bit hash that combines the FileIDHash with the encrypted 
    // KeyAddress.

//------------------------------------------------------------------------------
    
#define MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT (SKEIN1024_BLOCK_BYTES)
    // Minimum number of true random bytes to draw from a one-time pad key file 
    // for initializing the hash context used for making a password-conditioned 
    // pseudo-random stream. If the current password is longer than this size,
    // then the length of the password will be used instead for the number of
    // true random bytes to use for initializing the PasswordContext.
    
#define PASSWORD_HASH_BIT_COUNT (64)
    // Nominal output hash size in bits for the password-derived pseudo-random 
    // number generator. This is used to initialize the Skein1024 context. 
    // Sometimes the output hash length is varied to output different amounts
    // of pseudo-random bytes.
     
//------------------------------------------------------------------------------

#define SUMZ_HASH_BIT_COUNT  (64)      
    // Size of the SumZ checksum hash field in bits.
    
#define SUMZ_HASH_BYTE_COUNT (8)
    // Size of the SumZ checksum hash field in bytes.

/*------------------------------------------------------------------------------
| OT7Context
|-------------------------------------------------------------------------------
|
| PURPOSE: To organize information about an OT7 record being accessed.
|
| DESCRIPTION: The routines EncryptFileOT7() and DecryptFileOT7() use this 
| structure to hold the state of the encryption/decryption process.
|
| Grouping these variables and buffers into a single structure makes is easier
| to clear memory.
|
| This record supplements parameter information from the command line or from
| a key.map file.
|
| HISTORY: 
|    08Mar14 From DecryptFileOT7() and EncryptFileOT7().
------------------------------------------------------------------------------*/
typedef struct OT7Context
{
    u64 BodySize;
            // The size of the body section of the OT7 record in bytes. This is 
            // the binary format size. If base64 encoding is used, then the 
            // base64 format size will be larger than this value.
            //
    u32 BytesInTextBuffer;
            // Number of data bytes in the TextBuffer.
            //
    u32 BytesRead;
            // Number of bytes actually read when attempting to read from a 
            // file. 
            //
    u32 BytesWritten;
            // Number of bytes actually written when writing to a file.
            //
    u64 BytesToReadInField;
            // Number of bytes left to be read from the TextFill field
            // including both text and fill bytes.
            //
    u32 BytesToReadThisPass;
            // Number of bytes to read from the TextFill field on the current 
            // pass through the reading loop.
            //
    u64 BytesToWriteInField;
            // The total number of text and fill bytes left to be written in the
            // TextFill field during encryption.
            //
    u32 BytesToWriteThisPass;
            // The total number of bytes to write to the TextFill field on the 
            // current pass through the loop used to write chunks to the file. 
            // This can be up to twice the BLOCK_SIZE. This is the sum of text 
            // and fill bytes to be written on the current pass.
            //
    u8 ComputedHeaderKey[HEADERKEY_BYTE_COUNT];
            // HeaderKey computed from the KeyID, password, and key file.
            //
    FILEX EncryptedFile;
            // Extended file control block for the file containing the OT7 
            // record being decrypted. This supports the conversion of base64 to 
            // binary when the file is read.
            //
    u64 EncryptedFileSize;
            // Size of the encrypted file in bytes. This may be larger than the 
            // computed OT7 record size if the file format is base64.
            //
    u64 EndingAddress;
            // Address of the first byte in the key file following the key used 
            // for decrypting the OT7 record. This marks the end of the span of 
            // bytes to be erased if key file bytes are erased on decryption.
            //
    u8 ExtraKeyUsed;
            // Number of key bytes used in the key file prior to the KeyAddress.  
            // Key bytes may be used for generating the number of fill bytes. 
            // These extra key bytes need to be tracked so that they can be 
            // erased along with the bytes used to encrypt the OT7 record if the 
            // key erase option is used on encryption or decryption. Valid 
            // values for ExtraKeyUsed are 0 or 8.
            //
    s8 FileNameBuffer[MAX_FILE_NAME_SIZE]; // 512 bytes
            // A buffer for holding the name of the file embedded in the OT7 
            // record if there is one.
            //
    u16 FileNameSize;
            // Size of the FileName field read from the FileNameSize field of 
            // the OT7 record, a value from 0 to MAX_FILE_NAME_SIZE bytes.
            //
    u8 FillBuffer[FILL_BUFFER_SIZE]; // 512 bytes
            // Buffer for fill bytes used as padding in the TextFill field of an 
            // OT7 record. Fill byte values are pseudo-randomly generated from 
            // the password hash stream. This buffer should be the same size as 
            // TextBuffer to keep the text/fill byte interleaving logic simple.
            //
    u64 FillBytesToReadInField;
            // Number of fill bytes left to be read from the TextFill field.
            //
    u32 FillBytesToReadThisPass;
            // Number of fill bytes to be read from the TextFill field on the 
            // current pass, the lesser of the TEXT_BUFFER_SIZE and the number 
            // of fill bytes remaining in the TextFill field.
            //
    u64 FillBytesToWriteInField;
            // Number of fill bytes left to be written to the TextFill field.
            //
    u32 FillBytesToWriteThisPass;
            // Number of fill bytes to be written to the TextFill field on the 
            // current pass, the lesser of the TEXT_BUFFER_SIZE and the number 
            // of fill bytes remaining for the TextFill field.
            //
    u64 FillSize;
            // Number of fill bytes in the TextFill field, the value read from
            // the FillSize field of the OT7 record.
            //
    u8 FillSizeFieldSize;
            // Size of the FillSize field in bytes, a value from 0 to 8 which
            // depends on the number of fill bytes in the OT7 record.
            //
    u64 FoundKeyID;
            // KeyID found when searching the 'key.map' file for a match based 
            // on some search criteria such as the header of an OT7 record 
            // being decrypted.
            //
    s8* FoundPassword;
            // The password found to successfully decrypt the header, either 
            // PasswordForSearching, a password from the key definition, or the 
            // default password. This is a dynamically allocated copy of the
            // password that will need to be freed.
            //
    u8 Header[OT7_HEADER_SIZE];
            // Header of the OT7 record read from the encrypted file.
            //
    u8 IsTextByteNext;
            // The interleave flag used to separate text bytes from fill bytes 
            // in the TextFill field. 1 means that a plaintext byte should be 
            // read next, and 0 means that a fill byte should be read next.  
            //                
    u64 KeyAddress;
            // The KeyAddress decoded from the header of the OT7 record. This is 
            // the byte offset in the key file to begin when decrypting the OT7 
            // record.
            //
    u64 KeyBytesNeeded;
            // The number of key bytes needed for encrypting an OT7 record: one 
            // byte for each byte of the body plus all of the bytes needed for 
            // initialization of the password hash context and generation of the 
            // fill count. The password context needs to be initialized twice: 
            // once for the header key and once for encrypting the body.
            //
    FILE* KeyFileHandle;
            // File handle of the current key file.
            //
    s8* KeyFileName;
            // Name of the file used to decrypt the OT7 record, a zero-
            // terminated ASCII string. This is a reference to a string in the 
            // key file name list: that string gets deallocated when the file 
            // name list is freed.
            //
    s8 KeyFileNameBuffer[MAX_FILE_NAME_SIZE]; // 512 bytes
            // A buffer for holding the name of a key file generated from a 
            // KeyID.
            //
    u64 KeyFileSize;
            // Size of the key file in bytes.
            //
    u8 KeyHashBuffer[KEY_FILE_HASH_SIZE]; // 8 bytes
            // A key hash identifies a one-time pad key file based on the 
            // content of the file. This hash is computed from the signature of 
            // the current one-time pad key. This buffer is for the binary 
            // representation of an 8-byte key file hash. 
            //
    s8 KeyHashStringBuffer[KEY_FILE_HASH_STRING_BUFFER_SIZE]; // 17 bytes
            // A buffer used for the string representation of KeyHash[]. This is 
            // a zero-terminated ASCII string. This value persists during 
            // encryption so that it can be used to update the offset of the 
            // first unused key byte in the 'ot7.log' file.
            //
    u8 KeyIDHash128bit[KEYIDHASH128BIT_BYTE_COUNT];
            // The 16-byte hash used to encrypt the KeyID and KeyAddress.
            //
    u64 NumberErased;
            // Number of bytes erased from the key file if used key bytes are 
            // erased.
            //
    Skein1024Context PasswordContext;
            // Hash context for computing the password-conditioned pseudo-random 
            // stream used for decrypting the body of an OT7 record. This stream 
            // is also seeded with true random bytes from the key file used to 
            // decrypt the record.
            //
    s8* PasswordForSearching;
            // The password to use when searching for a key definition in the 
            // key.map that decrypts the header of the OT7 record.
            //
    FILE* PlaintextFile;
            // File handle of the file containing plaintext data.
            //
    u8 PseudoRandomKeyBuffer[KEY_BUFFER_SIZE]; // 1024 bytes
            // Buffer for bytes from the password-derived pseudo-random key used
            // for encryption and decryption of an OT7 record. 
            //
    u32 PseudoRandomKeyBufferByteCount;
            // Number of unused bytes in the PseudoRandomKeyBuffer. Bytes are 
            // used from the start of the buffer to the end.
            //
    u8 SizeBits;
            // Specifies the size of the TextSize and FillSize fields. The low 4 
            // bits is the number of bytes in the TextSize field. The high 4 
            // bits is the number of bytes in the FillSize field. 
            //
            //         7    6    5    4     3    2    1    0
            //       -----------------------------------------
            //       | FillSizeFieldSize | TextSizeFieldSize |
            //       -----------------------------------------
            //                 SizeBits Field Format
            //
    u64 StartingAddress;
            // Address of the first key byte used to produce the OT7 record
            // including those bytes pulled from the key file for the purpose of 
            // randomizing the fill byte count.
            //
    int Status;
            // Result code from a file operation such as fclose().
            //
    Skein1024Context SumZContext;
            // Hash context for computing the final checksum of an OT7 record 
            // stored in field SumZ.
            //
    u8 TextBuffer[TEXT_BUFFER_SIZE]; // 512 bytes
            // Buffer used for holding decrypted data, the plaintext of the
            // encrypted file as well as decrypted values from the fields before 
            // the TextFill field in the OT7 record.
            //
    u8 TextFillBuffer[TEXTFILL_BUFFER_SIZE]; // 1024 bytes
            // Buffer used for holding plaintext data interleaved with fill 
            // bytes during encryption and decryption of the TextFill field of 
            // an OT7 record. Other miscellaneous data may also be stored in 
            // this buffer temporarily.
            //
    u64 TextBytesToReadInField;
            // Number of text bytes left to be read from the TextFill field.
            //
    u32 TextBytesToReadThisPass;
            // Number of text bytes to be read from the TextFill field on the 
            // current pass, the lesser of the TEXT_BUFFER_SIZE or the number of 
            // text bytes remaining in the TextFill field.
            //
    u64 TextBytesToWriteInField;
            // Number of text bytes left to be written to the TextFill field.
            //
    u32 TextBytesToWriteThisPass;
            // Number of text bytes to write to the TextFill field on the
            // current pass, the lesser of the TEXT_BUFFER_SIZE or the number of 
            // text bytes left to be written to the TextFill field.
            //
    u64 TextSize;
            // Size of the plaintext in the OT7 record in bytes. This is the
            // value read from the TextSize field in the OT7 record.
            //
    u8 TextSizeFieldSize;
            // Size of the TextSize field in bytes, a value from 0 to 8 which
            // depends on the size of the plaintext in the OT7 record.
            //
    Item* TheKeyDefinition;
            // The item in the KeyMapList that refers to the beginning of the 
            // current key definition, a line of text such as "KeyID( 1 )" 
            // where the number uniquely identifies key definition in the key
            // map.
            //
    ThatItem CurrentKeyFileName; 
            // A reference to the current key file name in the list of all key
            // files associated with the current KeyID.
            //
    u64 TotalUsedBytes;
            // Total number of bytes in the key segment used to encrypt the OT7 
            // record. If key bytes are erased after use, then this is the 
            // amount that will be erased after decrypting the file.
            //
    u32 TrueRandomBytesRequiredForHashInitialization;
            // Number of true random bytes from the one-time pad key file
            // required to initialize the password hash context one time.
            //
    u8 TrueRandomKeyBuffer[KEY_BUFFER_SIZE]; // 1024 bytes
            // Buffer used for holding key data from the one-time pad file. This 
            // buffer is the same size as the TextFillBuffer so that there can 
            // be one key byte for each text/fill byte during block processing.
            //
    u64 UnusedBytes;
            // Number of unused key bytes in the current key file.
            
} OT7Context;

//------------------------------------------------------------------------------

void AppendItems( List* To, List* From );

int AugmentCommandLineParametersFromKeyDefinition( 
         List* KeyMapList, 
         Item* AKeyDefinition );

u32  CloseFileAfterReadingX( FILEX* F ); 
u32  CloseFileAfterWritingX( FILEX* F );

u32  ComputeKeyHash( 
        s8*   KeyFileName,
        FILE* KeyFileHandle,
        u8*   Hash,
        s8*   HashString );
        
void ComputeKeyIDHash128bit( 
        u8* HeaderKey,
        u64 KeyID, 
        s8* Password,
        u8* KeyIDHash128bit );

u32  ConvertASCIIHexToInteger( u8* Input, u32 InputLength );
s8*  ConvertBytesToHexString( u8* Buffer, u32 ByteCount );

s8*  ConvertIntegerToString64( u64 n );
void CopyBytes( u8* From, u8* To, u32 Count );
u32  CountString( s8* FirstByte );

u32  DecryptFileOT7();

u32  DecryptFileToBuffer( 
        OT7Context* d,
        u8* DataBuffer,
        u32 BytesToDecrypt );

u32  DecryptFileUsingKeyFile( OT7Context* d );

void DeinterleaveTextFillBytes( OT7Context* d );
void DeleteEmptyStringsInStringList( List* L );
void DeleteItem( Item* AnItem );
void DeleteItems( Item* First );
void DeleteList( List* L );
void DeleteListOfDynamicData( List* L );
void DeleteString( s8* S );
u32  DetectFormatOfEncryptedOT7File( s8* FileName );
s8*  DuplicateString( s8* AString );
void EmptyList( List* L );
            
u32 EncryptBufferToFile( 
        OT7Context* e,
        u8* DataBuffer,
        u32 BytesToEncrypt );
 
u32 EncryptFileOT7();

u32 EncryptFileUsingKeyFile( OT7Context* e );

u64 EraseUsedKeyBytesInOneTimePad( 
        OT7Context* c,
        u64 StartingAddress,
        u64 UsedBytesToErase );

void  ExtractItems( List* L, Item* FromItem, u32 ItemCount );
            
Item* ExtractTheItem( ThatItem* C );
        
u8*   FindNonWhitespaceByteInSegment( u8* Start, u8* End );

s8*   FindPasswordInKeyDefinition( 
            List* KeyMapList,
            Item* TheKeyDefinition );

s8*   FindStringInString( s8* SubString, s8* String );

u16   Get_u16_LSB_to_MSB( u8* Buffer );
u32   Get_u32_LSB_to_MSB( u8* Buffer );
u64   Get_u64_LSB_to_MSB( u8* Buffer );
u64   Get_u64_LSB_to_MSB_WithTruncation( u8* Buffer, u8 ByteCount );
u64   GetFileSize64( FILE* F );
u8    GetNextByteFromPasswordHashStream( OT7Context* c );
void  IdentifyDecryptionKey( OT7Context* d );
void  IdentifyEncryptionKey( OT7Context* c );
void  InitializeApplication();

u32   InitializeHashWithTrueRandomBytesAndPassword( 
            OT7Context* c,
            Skein1024Context* HashContext,
            u32   HashSizeInBits,
            s8*   Password );

void  InitializeParameters();
Item* InsertDataLastInList( List* L, u8* SomeData );
void  InsertItemLastInList( List* L, Item* AnItem );
void  InterleaveTextFillBytes( OT7Context* e );
u32   IsAnyItemsInList( List* L );
u32   IsItemAlone( Item* AnItem );
u32   IsItemFirst( Item* AnItem );
u32   IsItemLast( Item* AnItem );
u32   IsFileNameValid( s8* FileName );
u32   IsMatchingBytes( u8* A, u8* B, u32 Count );
u32   IsMatchingStrings( s8* A, s8* B );
u32   IsPrefixForString( s8* Prefix, s8* OtherString );
 
Item* LookupKeyDefinitionByIDStrings( 
            List* KeyMapList, 
            List* IDStringsList,
            u64*  FoundKeyID );

Item* LookupKeyDefinitionByKeyID( 
            List* KeyMapList, 
            u64   KeyID );
            
void LookupKeyDefinitionByOT7Header( 
            List*  KeyMapList, 
            s8*    PasswordForSearching,
            u8*    OT7HeaderToMatch,
            Item** KeyDefinition, 
            u64*   FoundKeyID,
            s8**   FoundPassword,
            u64*   KeyAddress );
            
u64 LookupOffsetOfFirstUnusedKeyByte( s8* KeyHashString );

int main( int argc, char* argv[] );

Item* MakeItem();
Item* MakeItemForData( u8* SomeData );
List* MakeList();
 
void  MarkItemAsFirst( Item* AnItem );
void  MarkItemAsLast( Item* AnItem );
void  MarkListAsEmpty( List* L );
u8    NumberOfSignificantBytes( u64 Number );

int   OpenFileX( 
            FILEX* ExtendedFileHandle,
            s8*    FileName, 
            s8     EncryptedFileFormat, 
            s8*    AccessMode );
 
FILE* OpenKeyFile( s8* KeyFileName );

int   ParseCommandLine( s16 argc, s8** argv );

u32 ParseFileNameParameter( 
        ParamString* FileNameParameter,
        s8*          FileNameString );

u32   ParseKeyIDFromKeyDefString( 
            s8*  KeyDefString,
            u64* ParsedKeyID );

u64   ParseUnsignedInteger( s8** StringCursor, s8* AfterBuffer );

u32   ParseWordOrQuotedPhrase( 
            s8** S, 
            s8*  OutputBuffer,
            u32  OutputBufferSize );
            
u32   ParseWordOrQuotedPhrasePreservingQuotes( 
            s8** S, 
            s8*  OutputBuffer,
            u32  OutputBufferSize );
            
u32   ParseWordsOrQuotedPhrase( 
            s8** S, 
            s8* OutputBuffer,
            u32 OutputBufferSize );

void  PickKeyID( 
            Param* KeyID,
            FILE*  KeyFileHandle,
            u64    FirstKeyID, 
            u64    LastKeyID );
        
void  PrintStringList( s8** AStringList );
void  Put_u16_LSB_to_MSB( u16 n, u8* Buffer );
void  Put_u32_LSB_to_MSB( u32 n, u8* Buffer );
void  Put_u64_LSB_to_MSB( u64 n, u8* Buffer );
void  Put_u64_LSB_to_MSB_WithTruncation( u64 n, u8* Buffer, u8 ByteCount );
s16   Read6BitWordX( FILEX* F );
u32   ReadByte( FILE* FileHandle, u8* BufferAddress );
u32   ReadByteX( FILEX* F, u8* ByteBuffer );
u32   ReadBytes( FILE*  FileHandle, u8* BufferAddress, u32 NumberOfBytes );
u32   ReadBytesX( FILEX* F, u8* BufferAddress, u32 NumberOfBytes );
List* ReadListOfTextLines( s8* AFileName );
void  ReadKeyMap( s8* AFileName, List* KeyMapStringList );
s32   ReadTextLine( FILE* AFile, s8* ABuffer, u32 BufferSize );
u32   ReadU64( FILE* F, u64* Result );
u32   ReportAvailableKeyBytes();
void  ReverseString( s8* A );
void  Skein_Get64_LSB_First( u64* dst, u8* src, u32 WordCount );
void  Skein_Put64_LSB_First( u8* dst, u64* src, u32 ByteCount );
void  Skein1024_Final( Skein1024Context* ctx, u8* hashVal );
void  Skein1024_Init( Skein1024Context* ctx, u32 hashBitLen );
void  Skein1024_Print( Skein1024Context* ctx );

void  Skein1024_Process_Block(
         Skein1024Context* ctx,
         u8* blkPtr,
         u32 blkCnt,
         u32 byteCntAdd );

u32   Skein1024_Test();
u32   Skein1024_TestCase( u8* MessageData, u32 MessageSize, u8* ExpectedResult );
void  Skein1024_Update( Skein1024Context* ctx, u8* msg, u32 msgByteCnt );
void  SkipWhiteSpace( s8** Here, s8* AfterBuffer );
void  SkipWhiteSpaceBackward( s8** Here, s8* BeforeBuffer );
u64   SelectFillSize( FILE* KeyFileHandle, u64 PlaintextSize );
s32   SetFilePosition( FILE* FileHandle, u64 ByteOffset );
u32   SetOffsetOfFirstUnusedKeyByte( s8* KeyHashString, u64 FirstUnusedByte );
void  StripCommentsInStringList( List* L );
void  StripLeadingWhiteSpaceInStringList( List* L );
void  StripTrailingWhiteSpaceInStringList( List* L );
void  ToFirstItem( List* L, ThatItem* C );
void  ToNextItem(ThatItem* C);
void  ToPriorItem( ThatItem* C );
u32   WriteByte( FILE* FileHandle, u8 AByte );
u32   WriteByteX( FILEX* FileHandleX, u8 ByteToWrite );
u32   WriteBytes( FILE* FileHandle, u8* BufferAddress, u32 AByteCount );
u32   WriteBytesX( FILEX* FileHandleX, u8* BufferAddress, u32 AByteCount );
u32   WriteListOfTextLines( s8* AFileName, List* L );
void  XorBytes( u8* From, u8* To, u32 Count );
void  ZeroBytes( u8* Destination, u32 AByteCount );
void  ZeroAllNumericParameters();
void  ZeroAllStringListParameters();
void  ZeroAllStringParameters();
void  ZeroAndFreeAllBuffers();
void  ZeroFillString( s8* S );
void  ZeroFillStringList( List* L );
 
/*------------------------------------------------------------------------------
| main
|-------------------------------------------------------------------------------
|
| PURPOSE: Main routine for OT7 one-time pad encryption command line tool.
|
| DESCRIPTION: This utility handles the encryption and decryption of files using
| one-time pad encryption. The output of the encryption process is a file 
| interchange format called OT7. The decryption process converts an OT7 file 
| back into a plaintext file.
|
| OT7 files can be stored in either in binary or base64 encoded format: 
|
|       base64 format is useful for sending OT7 files in email messages, and 
|
|       binary format is more compact and faster to process.
|
| USAGE: See the Help[] array above for the text of the help message printed
| by the '-h' option.
|
| HISTORY: 
|    12Oct13 
|    23Feb14 Made decryption the default operation if no other operation is
|            selected.
|    01Mar14 Reverted to printing help message if no operation is selected.
------------------------------------------------------------------------------*/
    // OUT: Result code from interpreting the command line function.
int //
main( int argc, char* argv[] )
{
    u8 IsPrintingExitMessage;
    
    // Initialize the OT7 application, setting default options.
    InitializeApplication();
    
    // Parse the command line parameters to set global variables.
    Result = ParseCommandLine( (s16) argc, (s8**) argv );
            
    // If an error occurred when parsing the command line, then print an error
    // and exit. 
    if( Result != RESULT_OK )
    {
        // If the verbose mode is enabled, then give the user some help. This 
        // output can be suppressed using the '-silent' option.
        if( IsVerbose.Value )
        {
            printf( "Invalid command. Type 'ot7 -h' for help.\n" );
        }
        
        // Return the result code.
        goto Exit;
    }
     
    // If usage info should be printed, then do it.
    if( IsHelpRequested.Value )
    {
        // Print the list of strings in the Help table.
        PrintStringList( Help );
    }

    // If a file should be encrypted, then do it.  
    if( IsEncrypting.Value )
    {
        // Encrypt the file specified on the command line.
        Result = EncryptFileOT7();
 
        // If an error occurred, then return the error code, skipping any other 
        // work requested on the command line.
        if( Result != RESULT_OK )
        {
            goto Exit;
        }      
    }
      
    // If a file should be decrypted, then do it.
    if( IsDecrypting.Value )
    {
        // Decrypt the file specified on the command line.
        Result = DecryptFileOT7();
 
        // If an error occurred, then return the error code, skipping any other 
        // work requested on the command line.
        if( Result != RESULT_OK )
        {
            goto Exit;
        }      
    }
  
    // If the number of available key bytes in a one-time pad file should be 
    // printed, then do it.
    if( IsReportingUnusedKeyBytes.IsSpecified && 
        IsReportingUnusedKeyBytes.Value )
    {
        Result = ReportAvailableKeyBytes();

        // If an error occurred, then return the error code, skipping any other 
        // work requested on the command line.
        if( Result != RESULT_OK )
        {
            goto Exit;
        }      
    }
    
    // If the hash function should be tested, then do it.
    if( IsTestingHash.Value )
    {
        // Run the Skein hash function test using standard reference data.
        Result = Skein1024_Test();
 
        // If an error occurred, then return the error code.
        if( Result != RESULT_OK )
        {
            goto Exit;
        }      
    }
     
    // Getting to this point implies success with Result = RESULT_OK (0).
    // Drop through to the common exit sequence also used by error exits.

///////    
Exit://
///////
    
    // If the verbose mode is enabled, then set a local flag to report final 
    // exit status after clearing working memory which includes the IsVerbose 
    // flag.
    if( IsVerbose.Value )
    {
        IsPrintingExitMessage = 1;
    }
    else
    {
        IsPrintingExitMessage = 0;
    }
    
    // Zero the working memory used by the OT7 application and free all
    // dynamically-allocated buffers.
    ZeroAndFreeAllBuffers();
    
    // If the verbose mode is enabled, then report final exit status.
    if( IsPrintingExitMessage )
    {
        printf( "All working buffers have been cleared.\n" );
         
        printf( "Exiting OT7 with result code %d.\n", Result );
        
        // Print a dividing line between OT7 sessions in verbose mode to make 
        // reading log files easier.
        printf( "--------------------------------------------------------------"
                "------------------\n" );
    }
 
    // Return result code to the calling application.
    return( Result );
}

/*------------------------------------------------------------------------------
| AppendItems
|-------------------------------------------------------------------------------
|
| PURPOSE: To move items from one list to the end of another.
|
| DESCRIPTION: The 'From' list is emptied of items after transfering them to 
| the 'To' list.
|
| HISTORY: 
|    04Feb97 Factored out of JoinLists().
|    28Feb14 Removed unused ListMark field code.
------------------------------------------------------------------------------*/
void
AppendItems( List* To, List* From )
{
    // If 'From' list is empty, just return.
    if( From->ItemCount == 0 )
    {
        return;
    }
      
    // If the 'To' list has existing items, then link them to the items from
    // the 'From' list.
    if( To->ItemCount )
    {
        // Link the next link of the 'To' list to the beginning of the 'From' 
        // list.
        To->LastItem->NextItem = From->FirstItem;
        
        // Link the prior link of the 'From' list to the end of the 'To' list.
        From->FirstItem->PriorItem = To->LastItem;
    }
    else // 'To' list is empty. 
    {
        // Set the first item pointer in the destination list from the source 
        // list
        To->FirstItem = From->FirstItem;
    }
    
    // Set the last item pointer in the destination list from the source 
    // list.
    To->LastItem = From->LastItem;
    
    // Add the counts of the two lists.
    To->ItemCount += From->ItemCount;
          
    // Clear the list count & pointers for the 'From' list.
    MarkListAsEmpty( From );
}

/*------------------------------------------------------------------------------
| AugmentCommandLineParametersFromKeyDefinition
|-------------------------------------------------------------------------------
|
| PURPOSE: To apply parameters from a key definition to the task of encrypting 
|          or decrypting a file.
|
| DESCRIPTION: Augments the command line parameters with settings from a given 
| key definition, but doesn't override any parameters already given on the 
| command line. 
|
| Parameters from the key definition are fed one by one to the normal command 
| line parser, ParseCommandLine().
|
| HISTORY: 
|    23Dec13 
|    19Feb14 Minor edits involving name changes and checks for buffer overruns.
|    22Feb14 Factored out ParseWordOrQuotedPhrase() as a separate routine.
|    23Mar14 Replaced ParseWordOrQuotedPhrase with 
|            ParseWordOrQuotedPhrasePreservingQuotes to fix quotes lost when
|            passing parameter values to the command line parser.
------------------------------------------------------------------------------*/
    // OUT: Result code, defined by symbols starting with 'RESULT_', where 0 is
    //      no error.
int //
AugmentCommandLineParametersFromKeyDefinition( 
    List* KeyMapList,
            // The contents of a "key.map" file, a list of strings where each
            // string is a line of text. Leading and trailing whitespace has
            // been removed from each line. Comments have been stripped out.
            //
    Item* TheKeyDefinition )
            // The place in the KeyMapList where the key definition begins, a
            // line of test beginning with the phrase "KeyID".
{
    s8* S;
    u32 t;
    u32 v;
    s16  argc;
    s8** argv;
    ThatItem C;
    u32 Result;
    static s8* ParameterTagAndValue[3];
    static s8 ParameterTagString[MAX_PARAMETER_TAG_SIZE];
    static s8 ParameterValueString[MAX_PARAMETER_VALUE_SIZE];
    
    // Link the 3-item string pointer buffer to the buffers used for holding
    // each parameter tag string and corresponding value string. A pointer to
    // this structure is equivalent to a command line 'argv' pointer.
    
    // The command line parser expects the application name in the first string
    // so put it there.
    ParameterTagAndValue[0] = APPLICATION_NAME_STRING; 
    
    // The next one or two strings will be the parameter fed to the parser from
    // the key definition file.
    ParameterTagAndValue[1] = (s8*) &ParameterTagString[0];
    ParameterTagAndValue[2] = (s8*) &ParameterValueString[0];
    
    // Use argv to to refer to the 3-item string buffer.
    argv = (s8**) &ParameterTagAndValue[0];
     
    // Set up a list cursor to refer to the given key definition in the key map 
    // list.
    C.TheList = KeyMapList;
    C.TheItem = TheKeyDefinition;
    
    // Here's the current situation:
    //
    //   C.TheItem->DataAddress ===> "KeyID( 123 )"
    //                                {
    //                                   ...the parameters of the key...
    //                                }
    
    // Advance past the "KeyID" string to the next line.
    ToNextItem(&C);

    // Process each line of the key definition, stopping when the end of the
    // definition is reached. Allow for the possibility that the user forgot 
    // to mark the end of the definition with a "}" by treating the end of 
    // the list, or the beginning of a new definition as the end of the 
    // definition.
    while( C.TheItem && 
           ( IsPrefixForString( "}", (s8*) C.TheItem->DataAddress ) == 0) &&
           ( IsPrefixForString( "KeyID", (s8*) C.TheItem->DataAddress ) == 0) )
    {
        // If the current string contains a parameter beginning with a '-'
        // character, then process it as a command line parameter.
        if( IsPrefixForString( "-", (s8*) C.TheItem->DataAddress ) )
        {
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Read parameter: [%s]\n", 
                         (s8*) C.TheItem->DataAddress );
            }

            // We need to split the parameter string into to two parts so that
            // it will appear to the command line parser in the same way it 
            // would if delivered via the command line.
            
            // Use S to refer to the beginning of the parameter string.
            //
            // This is the situation:
            //
            //     S
            //     |
            //     v
            //     -keyfile file1.key
            //
            S = (s8*) C.TheItem->DataAddress;
            
            // Parse the first word or quoted phrase from the string, removing 
            // any quotes. Use 't' to count the number of bytes in the tag 
            // string parsed from the text line.  
            t = ParseWordOrQuotedPhrase( 
                    &S,   // IN/OUT: Address of the address of the current 
                          //         character in the string being parsed.
                          //
                    (s8*) &ParameterTagString[0],
                          // Address of the output buffer where the word or 
                          // phrase should be placed.
                          //
                    MAX_PARAMETER_TAG_SIZE );
                          // Size of the output buffer in bytes.
               
            // This is the situation:
            //
            //             S
            //             |
            //             v
            //     -keyfile file1.key
            // or  -keyfile 'a file name with spaces.key'
            // or  -keyfile "a file name with spaces.key"
 
            // Parse the next word or quoted phrase from a string, removing any 
            // quotes. Use 'v' to count the number of bytes in the value string
            // parsed from the text line. Some tags don't have corresponding
            // value string.
            v = ParseWordOrQuotedPhrasePreservingQuotes( 
                    &S,   // IN/OUT: Address of the address of the current 
                          //         character in the string being parsed.
                          //
                    (s8*) &ParameterValueString[0],
                          // Address of the output buffer where the word or 
                          // phrase should be placed.
                          //
                    MAX_PARAMETER_VALUE_SIZE );
                          // Size of the output buffer in bytes.
              
            // If there is a value associated with the tag, then pass the 
            // parameter to the command line parser as three strings.
            if( v )
            {
                // There is a value part for this parameter so there are
                // 3 strings including the application name string.
                argc = 3;
            }
            else // The parameter just consists of a tag only.
            {
                argc = 2;
            }
            
            // Feed the parameter to the command line parser.
            //
            // OUT: Result code to be passed back to the calling application, 
            //      one of the values with the prefix 'RESULT_...'.
            Result = 
                ParseCommandLine( 
                    argc,
                        // Number of whitespace delimited words on the command 
                        // line, including the name of the application.
                        // 
                    argv );
                        // An array of strings formed as from the command line.
            
            // If there was an error, then just return the error code.
            if( Result != RESULT_OK )
            {
                goto CleanUp;
            }
        }        

        // Advance to the next line of the key definition.
        ToNextItem(&C);
    }
    
    // At this point the key definition was processed without error.
    
    // Return RESULT_OK result code below.
    Result = RESULT_OK;

//////////    
CleanUp://
//////////  
  
    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential
    // for information leakage.
    //--------------------------------------------------------------------------
    
    // Zero the local variables except for Result.
    S = 0;
    t = 0;
    v = 0;
    argc = 0;
    argv = 0;
      
    // Zero the Item cursor record.
    ZeroBytes( (u8*) &C, sizeof(ThatItem) );
    
    // Zero the ParameterTagAndValue buffer.
    ZeroBytes( (u8*) &ParameterTagAndValue[0], sizeof(ParameterTagAndValue) );
    
    // Zero the ParameterTagString buffer.
    ZeroBytes( (u8*) &ParameterTagString[0], MAX_PARAMETER_TAG_SIZE );
    
    // Zero the ParameterValueString buffer.
    ZeroBytes( (u8*) &ParameterValueString[0], MAX_PARAMETER_VALUE_SIZE );
     
    // Zero all of the stack locations used to pass parameters into this
    // routine.
    KeyMapList = 0;
    TheKeyDefinition = 0;
    
    // Return the result code produced when parsing the definition.
    return( Result );
}

/*------------------------------------------------------------------------------
| CloseFileAfterReadingX
|-------------------------------------------------------------------------------
| 
| PURPOSE: To close a generic file after reading base64 or binary data.
|
| DESCRIPTION: The format of an OT7 encrypted file can be either binary or
| base64. This handles closing the underlying file and clearing the fields in 
| the extended file control block.
|
| HISTORY: 
|    23Mar14 From CloseFileAfterWritingX().
------------------------------------------------------------------------------*/
     // OUT: Status flag equal to 1 if there was an error, or 0 if closed OK.
u32  //
CloseFileAfterReadingX( FILEX* F ) 
{
    u32 Status;
     
    // Use 0 to mean a status of no errors.
    Status = 0;
 
    // Close the file if it is open. 
    if( F->FileHandle )
    {
        // Close the underlying file using the standard file handle.
        Status = fclose( F->FileHandle );
        
        // If Status is non-zero, then use 1 to mean there was an error.
        if( Status )
        {
            Status = 1;
        }
     
        // Zero the file handle to avoid attempt to reclose.
        F->FileHandle = 0;
    }
    
    // Zero the other fields used in the extended file control block.
    F->FileFormat = 0;
    F->FilePositionInBytes = 0;
    F->FilePositionIn6BitWords = 0;
    F->AByte = 0;
    F->BByte = 0;
    F->CByte = 0;
    F->LastSymbolRead = 0;
    
    // Return 1 if there was an error, or 0 if file closed OK.
    return( Status );
}
   
/*------------------------------------------------------------------------------
| CloseFileAfterWritingX
|-------------------------------------------------------------------------------
| 
| PURPOSE: To close a generic file after writing base64 or binary data.
|
| DESCRIPTION: The format of an OT7 encrypted file can be either binary or
| base64. This handles writing any required padding characters ('=') for base64.
|
| HISTORY: 
|    26Oct13 
|    03Mar14 Fixed case where bits in buffers were not written before appending
|            padding bytes.
------------------------------------------------------------------------------*/
     // OUT: Status flag equal to 1 if there was an error, or 0 if closed OK.
u32  //
CloseFileAfterWritingX( FILEX* F ) 
{
    u32 Status;
    u32 WordIndex;
    u32 NumberWritten;
    
    // Use 0 to mean a status of no errors.
    Status = 0;
      
    // Close the file according to the file format.
    switch( F->FileFormat )
    {
        // If writing in binary format, then call the ordinary file close
        // routine.
        case OT7_FILE_FORMAT_BINARY:
        {
            // Nothing extra needs to be written when closing a binary file.
        
            // Go close the underlying file in the usual way.
            break;
        } 
        
        //----------------------------------------------------------------------
    
        // If writing in base64 format, then write any buffered data and append
        // padding bytes needed to make an even multiple of 24 bits.
        case OT7_FILE_FORMAT_BASE64:
        {
            // In base64 encoding, 6-bit words are packed into bytes using a
            // 4-in-3 byte arrangement as shown here:
            //
            //         word index=1
            //               |
            //            -------
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // where: 
            //
            //      000000 is the first 6-bit word, 111111 is the second, and 
            //             so on.
            //
            // Whole bytes are written into buffers AByte, BByte, and CByte, 
            // and from those buffers 6-bit words are written to disk as they
            // become complete words. This may leave partial 6-bit words in the 
            // buffers when it comes time to close the file. 
            //
            // If the ending word index refers to a 6-bit word that spans bytes, 
            // such as cases 1 and 2, then the partially completed 6-bit word 
            // will need to be written before writing padding bytes.
            
            // Compute the word index that refers to a 6-bit word in a 24-bit 
            // field.
            WordIndex = F->FilePositionIn6BitWords & 3;
            
            // If the word index is either 1 or 2, then write a zero byte to
            // flush the partial byte in buffers AByte or BByte to disk.
            if( (WordIndex == 1) || (WordIndex == 2) )
            {
                // Write the byte using the same routine used for writing 
                // data bytes, WriteByteX(). 
                //
                // OUT: Number of bytes written: either 1 or 0 if there was an 
                // error. F->FilePositionIn6BitWords is also updated.
                NumberWritten = WriteByteX( F, 0 );
                
                // If a write error occurred, then close the file and return
                // the error code 1.
                if( NumberWritten == 0 )                
                {
                    // Close the file to avoid leaving an open handle.
                    fclose( F->FileHandle );
                    
                    // Zero the file handle to avoid attempt to reclose.
                    F->FileHandle = 0;
                    
                    // Return 1 to mean an error occurred.
                    return( 1 );
                } 
            }

            // Now padding bytes may need to be added to end the stream on a
            // 24-bit boundary.
            //
            // If word index is 0, then no padding bytes are needed.
            // if word index is 3, then one padding byte is needed.
            // If word index is 2, then two padding bytes are needed.
            // If word index is 1, then three padding bytes are needed.
            //
            // Provided that BASE64_LINE_LENGTH is always a multiple of 4, then
            // there is no need to check for and insert a CRLF when writing 
            // padding bytes.
            
            // Compute the word index that refers to a 6-bit word in a 24-bit 
            // field.
            WordIndex = F->FilePositionIn6BitWords & 3;

            // Write padding bytes until word index is zero.
            while( WordIndex ) 
            {
                // Write a padding byte ('=') to the file at the current file 
                // position, returning the number of bytes written.
                NumberWritten = WriteByte( F->FileHandle, BASE64_PAD_CHAR );
                
                // If the letter was written to the file, advance the
                // 6-bit word file position by one.
                if( NumberWritten == 1 )
                {
                    F->FilePositionIn6BitWords++;
                } 
                else // A write error occurred.
                {
                    // Close the file to avoid leaving an open handle.
                    fclose( F->FileHandle );
                    
                    // Zero the file handle to avoid attempt to reclose.
                    F->FileHandle = 0;
                    
                    // Return 1 to mean an error occurred.
                    return( 1 );
                } 
                
                // Update the word index that refers to a 6-bit word in a 
                // 24-bit field.
                WordIndex = F->FilePositionIn6BitWords & 3;
            }
        }
    }
    
    // Close the file, flushing any buffered data to disk.
    Status = fclose( F->FileHandle );
    
    // Zero the file handle to avoid attempt to reclose.
    F->FileHandle = 0;
    
    // If Status is non-zero, then use 1 to mean there was an error.
    if( Status )
    {
        Status = 1;
    }
     
    // Return 1 if there was an error, or 0 if file closed OK.
    return( Status );
}

/*------------------------------------------------------------------------------
| ComputeKeyHash
|-------------------------------------------------------------------------------
|
| PURPOSE: To compute a hash string to identify a one-time pad key file.
|
| DESCRIPTION: The first 32 bytes of a one-time pad key file are reserved as 
| the signature of the file and not used for encryption. An 8-byte KeyHash is 
| computed from this 32-byte signature.
|
| This routine reads the internal file signature and converts it to an 8-byte
| KeyHash, also expressed as a 16-byte hex string, eg. "2819ED98F3020672".
|
| This routine may reposition the file pointer.
|
| HISTORY: 
|    29Dec13 
|    10Feb14 Added return of binary form of key hash as well as string form.
|    24Feb14 Added status message with key hash in verbose mode.
------------------------------------------------------------------------------*/
    // OUT: RESULT_OK if successful, or some other status code if there was an
    //      error.
u32 //
ComputeKeyHash( 
    s8*   KeyFileName,
            // File name of the one-time pad key file, a zero-terminated ASCII
            // string.
            //
    FILE* KeyFileHandle,
            // File handle of a one-time pad key file, opened for read-only or
            // read/write access.
            //
    u8*   Hash,
            // OUT: Output buffer for the key file hash in binary form. The
            //      size of the buffer is KEY_FILE_HASH_SIZE = 8 bytes.
            //
    s8*   HashString )
            // OUT: Output buffer for the key hash string. Must be at least
            // (KEY_FILE_HASH_SIZE*2) + 1 = 17 bytes.
{
    u8  i;
    s32 SeekStatus;
    u32 ReadStatus;
    u8  Sig[KEY_FILE_SIGNATURE_SIZE];
       
    // Set the file position of the key file to the first byte where the
    // 32-byte file signature begins.
    SeekStatus = SetFilePosition( KeyFileHandle, 0 );
    
    // If unable to seek to the beginning of the file, then fail with the 
    // result code used for an error, 1.
    if( SeekStatus != 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't set file position in file '%s'.\n", 
                    KeyFileName );
        }

        return( RESULT_CANT_SEEK_IN_KEY_FILE );
    }
    
    // Read the file signature to a local buffer.
    //
    // OUT: Returns the number of bytes read, or MAX_VALUE_32BIT if error or 
    //      EOF.
    ReadStatus =
        ReadBytes( 
            KeyFileHandle,
                // Handle to an open file.
                //
           (u8*) &Sig[0], 
                // Destination buffer for the data read from the file.
                //
           (u32) KEY_FILE_SIGNATURE_SIZE );   
                // Number of bytes to read.

    // If the number of bytes read was not the number requested, then fail and
    // return the error code.
    if( ReadStatus != KEY_FILE_SIGNATURE_SIZE )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read key file '%s'.\n", KeyFileName );
        }

        return( RESULT_CANT_READ_KEY_FILE );
    }
    
    // Compute the FileID hash from the file signature by slicing the file
    // signature into four parts and XOR'ing them byte-by-byte.
    for( i = 0; i < KEY_FILE_HASH_SIZE; i++ )
    {
        // Compute one byte of the hash from 4 bytes of the file signature.
        Hash[i] = Sig[i] ^ 
                  Sig[i+KEY_FILE_HASH_SIZE] ^ 
                  Sig[i+(KEY_FILE_HASH_SIZE*2)] ^ 
                  Sig[i+(KEY_FILE_HASH_SIZE*3)];
         
        // Zero the signature bytes after they have been used to compute
        // the hash.         
        Sig[i] = 0; 
        Sig[i+KEY_FILE_HASH_SIZE] = 0;
        Sig[i+(KEY_FILE_HASH_SIZE*2)] = 0;
        Sig[i+(KEY_FILE_HASH_SIZE*3)] = 0;
    }
    
    // Convert the hash to an ASCII hex string.  
    for( i = 0; i < KEY_FILE_HASH_SIZE; i++ )
    {
        // Compute two bytes of the hash string from each hash byte.
        HashString[i*2]     = HexDigit[ (Hash[i] & 0xF0) >> 4 ];
        HashString[(i*2)+1] = HexDigit[ Hash[i] & 0x0F ];
    }
    
    // Append a zero to terminate the string.
    HashString[KEY_FILE_HASH_SIZE*2] = 0;
    
    // Print a status message if in verbose mode.
    if( IsVerbose.Value )
    {
        printf( "Key file hash is '%s'.\n", HashString );
    }
       
    // Return zero to mean success.
    return( RESULT_OK );
}

/*------------------------------------------------------------------------------
| ComputeKeyIDHash128bit
|-------------------------------------------------------------------------------
|
| PURPOSE: To compute a hash for encrypting KeyID and KeyAddress values in the 
|          header of an OT7 record.
|
| DESCRIPTION: This routine makes a hash value that covers 16 bytes of an OT7
| record header as shown here:
| 
|                      H E A D E R         
|                     ==========================<--- The hash spans this part 
|         --------------------------------------     of the header.
|         | HeaderKey | KeyIDHash | KeyAddress |      
|         ------------+-----------+------------+ 
|         0           8          16           24                             
|         |             
|         Byte Offset
|
| Note that the field called 'KeyIDHash' is actually only the first 8 bytes of
| the 16-byte hash value produced by this routine. The second 8 bytes is used 
| for encrypting the KeyAddress.
|
| The KeyIDHash128bit hash is computed as follows:
|    
|   KeyIDHash128bit = Skein1024 Hash Function{ HeaderKey, KeyID, Password }
|         
| where:
|    
|     HeaderKey is the 8-byte value from the HeaderKey field of an OT7 record.
|         
|     KeyID identifies a key definition by number. This is a value associated
|     with a one-time pad key used to encrypt an OT7 record. 
|           
|     Password is the current password parameter, either entered on the command
|     line, from a key definition, or the default password built into this
|     command line tool.
|
| HEADER SECURITY: An attacker with the header of an OT7 record can exhaustively 
| generate all possible (KeyID,Password) pairs until a matching KeyIDHash is 
| found. Since many (KeyID,Password) pairs can produce the same KeyIDHash, 
| finding a positive match is not a conclusive way of identifying a KeyID and 
| password, but it does narrow the field. To make that field as big as possible,
| KeyID numbers and passwords should be randomly generated, and long passwords 
| should be used. Changing passwords and KeyID's also improves security. 
|
| HISTORY: 
|    18Feb14 Added return of binary form of key hash as well as string form.
------------------------------------------------------------------------------*/
void
ComputeKeyIDHash128bit( 
    u8* HeaderKey,
            // The HeaderKey value of an OT7 record header. This is an 8-byte 
            // hash.
            //
    u64 KeyID, 
            // KeyID identifies a key definition by number. This is a value 
            // associated with a one-time pad key used to encrypt an OT7
            // record. 
            //
    s8* Password,
            // Password is the current password parameter, either entered on the
            // command line, from a key definition, or the default password.
            //
    u8* KeyIDHash128bit )
            // OUT: Output buffer for the 128-bit hash produced by this routine.
{
    static u8 KeyIDLSB_to_MSB[8];
    static Skein1024Context KeyIDHash128bitContext;
                // Static buffers are used in this routine to avoid taking up 
                // too much stack space.
   
    // Initialize the hash context for producing a 128-bit hash.
    Skein1024_Init( &KeyIDHash128bitContext, KEYIDHASH128BIT_BIT_COUNT );

    // Feed the HeaderKey into the KeyIDHash128bitContext hash context.
    Skein1024_Update( 
        &KeyIDHash128bitContext, 
        &HeaderKey[0], 
        HEADERKEY_BYTE_COUNT );
        
    // Save the 64-bit KeyID into a buffer in LSB-to-MSB order.    
    Put_u64_LSB_to_MSB( KeyID, &KeyIDLSB_to_MSB[0] );
        
    // Feed the KeyID into the KeyIDHash128bitContext hash context in 
    // LSB-to-MSB order.
    Skein1024_Update( &KeyIDHash128bitContext, &KeyIDLSB_to_MSB[0], 8 );
            
    // Feed the password into the hash context.
    Skein1024_Update( 
        &KeyIDHash128bitContext, (u8*) Password, CountString(Password) );
          
    // Compute the KeyIDHash128bit value and put it into the output buffer.
    Skein1024_Final( &KeyIDHash128bitContext, KeyIDHash128bit );
    
    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential
    // for information leakage.
    //--------------------------------------------------------------------------

    // Zero the hash context buffer.
    ZeroBytes( (u8*) &KeyIDHash128bitContext, sizeof(Skein1024Context) );
    
    // Zero the buffer used to reorder the bytes of the KeyID.
    ZeroBytes( (u8*) &KeyIDLSB_to_MSB[0], sizeof(KeyID) );
    
    // Zero all of the stack locations used to pass parameters into this
    // routine.
    HeaderKey = 0;
    KeyID = 0;
    Password = 0;
    KeyIDHash128bit = 0;
}                         

/*------------------------------------------------------------------------------
| ConvertASCIIHexToInteger
|-------------------------------------------------------------------------------
|
| PURPOSE: To convert an ASCII hex string of up to 8 digits into an integer.
|
| DESCRIPTION: This routine converts ASCII hex digits representing nibbles into
| their corresponding binary value.
|
| The first non-hex digit encountered in the input string ends the conversion.
|
| EXAMPLE:
|
|        IntegerResult = ConvertASCIIHexToInteger( (u8*) "8BEC8B", 6 );
|
| HISTORY:  
|    20Oct13
------------------------------------------------------------------------------*/
    // OUT: Integer value of the hex digits.
u32 //
ConvertASCIIHexToInteger( 
    u8* Input, 
        // Input buffer containing ASCII hex digits. 
        //
    u32 InputLength )
        // Number of input characters, from 0 to 8.
{
    u32 IntegerResult;
    u8  c;
    u8  n;
      
    // Initialize the integer accumulator to zero.
    IntegerResult = 0;
     
    // Until the end of the input data is reached or a non-hex digit is found.
    while( InputLength )
    {
        // Get the next character, advancing the input pointer by one.
        c = *Input++;
        
        // If the character is an ASCII hex digit, append it to the integer.
        if( IsHexDigit( (s8) c ) )
        {
            // Convert the character to a binary nibble.
            n = HexDigitToBinary[ c - '0' ];

            // Shift the integer result over by 4-bits to make room for the
            // next 4-bit word.
            IntegerResult <<= 4;
            
            // OR in the current nibble.
            IntegerResult |= n;
        } 
        else // Not a hex digit, so just return the accumulated result.
        {
            return( IntegerResult );
        }
         
        // Count the input character as processed.
        InputLength--;
    }
    
    // Return the integer equivalent of the input string.
    return( IntegerResult );
}

/*------------------------------------------------------------------------------
| ConvertBytesToHexString
|-------------------------------------------------------------------------------
|
| PURPOSE: To produce a ASCII hex string to represent a series of bytes.
|
| DESCRIPTION: Makes an ASCII number in a global buffer and returns the address
| of the buffer. 
|
| EXAMPLE:        MyString = ConvertBytesToHexString( Buf, 8 );
|
| HISTORY: 
|    02Mar14 From ComputeKeyHash() and ConvertIntegerToString64().
------------------------------------------------------------------------------*/
    // OUT: Address of the string corresponding to the input data segment.
s8* //
ConvertBytesToHexString( u8* Buffer, u32 ByteCount )
{
    s32 i;
    u32 SizeOfResultString;
    
    // Calculate the size of the result string including the zero terminator
    // byte.
    SizeOfResultString = (ByteCount * 2) + 1;
    
    // If the number of bytes exceed the size of the HexStringBuffer, then
    // limit the number of bytes to the size available.
    if( SizeOfResultString > HEX_STRING_BUFFER_SIZE )
    {
        ByteCount = (HEX_STRING_BUFFER_SIZE - 1) >> 1;
    }
     
    // Start the byte counter at 0.
    i = 0;
    
    // Convert the input bytes to an ASCII hex string.  
    for( i = 0; i < ByteCount; i++ )
    {
        // Compute two ASCII hex digits from each data byte.
        HexStringBuffer[i*2]     = HexDigit[ (Buffer[i] & 0xF0) >> 4 ];
        HexStringBuffer[(i*2)+1] = HexDigit[ Buffer[i] & 0x0F ];
    }
    
    // Append a zero to terminate the string.
    HexStringBuffer[ByteCount*2] = 0;
      
    // Return the string address.
    return( (s8*) &HexStringBuffer[0] );
}

/*------------------------------------------------------------------------------
| ConvertIntegerToString64
|-------------------------------------------------------------------------------
|
| PURPOSE: To produce a decimal ASCII string equivalent to an unsigned 64-bit 
|          integer.
|
| DESCRIPTION: Makes an ASCII number in a static buffer and returns the address
| of the buffer. 
|
| EXAMPLE:           MyString = ConvertIntegerToString( 123 );
|
| HISTORY: 
|    09Nov13 Changed to support 64-bit integers with static buffer.
|    26Jan13 Revised to be unsigned rather than signed.
------------------------------------------------------------------------------*/
    // OUT: Address of the string corresponding to n, in a static buffer.
s8* //
ConvertIntegerToString64( u64 n )
{
    static s8 s[22];
    s32 i;
     
    // Start the byte counter at 0.
    i = 0;

////////////    
NextDigit://
////////////    

    // Divide n by 10, converting the remainder to an ASCII digit.  
    s[i++] = (s8) (n % 10 + '0');
    
    // Move the decimal point over by one digit.
    n /= 10;
    
    // If more significant figures exist, go convert the next digit.
    if( n > 0 ) 
    {
        goto NextDigit;
    }
    
    // Add zero end-of-string byte.
    s[i] = 0; 
    
    // Reverse the order of the digits.
    ReverseString( s );
    
    // Return the string address.
    return( (s8*) &s[0] );
}

/*------------------------------------------------------------------------------
| CopyBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To copy a range of bytes from one place to another.
|
| DESCRIPTION: Correctly handles an overlapping series of bytes. 
|
| EXAMPLE:                CopyBytes( From, To, 5 );
|
| NOTE: This is currently quite slow since it does a byte-by-byte copy.  This 
| could be optimized to move larger chunks of data where the processor supports
| it. 
|
| HISTORY: 
|    25Aug89 
|    31Aug89 Added overlapping capability.
------------------------------------------------------------------------------*/
void
CopyBytes( u8* From, u8* To, u32 Count )
{
    if( From >= To )
    {
        while( Count-- )
        {
            *To++ = *From++;
        }
    }
    else
    {
        To   += Count;
        From += Count;
        
        while( Count-- )
        {
            *--To = *--From;
        }
    }
}

/*------------------------------------------------------------------------------
| CountString
|-------------------------------------------------------------------------------
|
| PURPOSE: To count the data bytes in a 0-terminated string. 
|
| DESCRIPTION: The terminating 0 is not included in the count.
|
| EXAMPLE:            AByteCount = CountString( MyString );
|
| HISTORY: 
|    31Aug89 
|    15Feb93 changed to return u32 instead of u16.
|    01Jan96 chaged to use pointer instead of indexed array.
|    01Dec13 Improved efficiency.
|    01Feb14 Now returns zero if string address is zero.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes in the string, not counting the zero at the end.
u32 //
CountString( s8* FirstByte )
{
    s8* End;
    
    // If the string address is invalid, then return zero as the string length.
    if( FirstByte == 0 )
    {
        return( 0 );
    }

    // Initialize byte cursor End to point to the first byte of the string.
    End = FirstByte;

///////////
NextByte://
///////////

    // If the current byte is non-zero, then advance the cursor by one byte.
    if( *End++ )
    {
        // Go test the next byte.
        goto NextByte;
    }
    
    // At this point End refers to the zero-terminator byte.
  
    // Subtract the starting address from the ending address, and return the
    // number of bytes in the string, not including the zero at the end.
    return( (u32) (End - FirstByte) );
}

/*------------------------------------------------------------------------------
| DecryptFileToBuffer
|-------------------------------------------------------------------------------
|
| PURPOSE: To decrypt data from a file to a buffer. 
|
| DESCRIPTION: Decrypts in blocks no larger than KEY_BUFFER_SIZE bytes.
|
| Uses TrueRandomKeyBuffer[] to store key bytes read from the one-time pad file.
|
| Uses names of the one time pad file and the encrypted file to report error
| messages, KeyFileName and NameOfEncryptedInputFile.
|
| On exit, TrueRandomKeyBuffer[] is cleared to zero and DataBuffer holds 
| plaintext.
|
| HISTORY: 
|    26Dec13 From EncryptBufferToFile().
|    17Feb14 Added pseudo-random key encryption.
|    27Feb14 Revised to generate uniform blocks of pseudo-random data, buffering
|            the unused portion between calls to this routine.
|    28Feb14 Removed hash size change on finalization. Factored out
|            GetNextByteFromPasswordHashStream(). Removed zeroing of the
|            PseudoRandomKeyBuffer[] since it needs to persist between calls to
|            this routine.
|    15Mar14 Revised to use OT7Context record.
------------------------------------------------------------------------------*/
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.
u32 //
DecryptFileToBuffer( 
    OT7Context* d,
        // Context of a file in the process of being decrypted.
        //
    u8* DataBuffer,
        // Address of the output buffer where decrypted data is to be written. 
        //
    u32 BytesToDecrypt )
        // Number of bytes to decrypt.
{
    u32 i;
    u32 Result;
    u32 BytesRead;
    u8* InDataBuffer;
    u32 BytesLeftToDecrypt;
    u32 BytesReadThisPass;
    u32 BytesToDecryptThisPass;
    
    // Start with no errors detected.
    Result = RESULT_OK;
    
    // Refer to the first byte location in the data buffer using a separate
    // pointer. This is needed in case of error so that partially decrypted 
    // data in DataBuffer can be erased.
    InDataBuffer = DataBuffer;
    
    // Set the number of bytes left to be decrypted to the given amount.
    BytesLeftToDecrypt = BytesToDecrypt;
     
    // Decrypt as long as bytes remain to be decrypted.
    while( BytesLeftToDecrypt )
    {
        // Calculate the number of bytes to read on this pass, defaulting to 
        // the key buffer size.
        BytesToDecryptThisPass = KEY_BUFFER_SIZE;

        // If there is less than a full block left to read, then just read
        // what is available.
        if( BytesToDecryptThisPass > BytesLeftToDecrypt )
        {
            BytesToDecryptThisPass = BytesLeftToDecrypt;
        }
  
        // Read a block of key bytes to the TrueRandomKeyBuffer.
        BytesRead = ReadBytes( d->KeyFileHandle, 
                               d->TrueRandomKeyBuffer,
                               BytesToDecryptThisPass );

        // If the key file could not be read, then return with an error  
        // message.
        if( BytesRead != BytesToDecryptThisPass )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't read key file '%s'.\n", 
                         d->KeyFileName );
            }

            // Set the result code to be returned by this routine.
            Result = RESULT_CANT_READ_KEY_FILE;
    
            // Exit, returning result to mean an error occurred.
            goto Exit;
        }

        // Read encrypted data bytes to the output buffer.
        BytesReadThisPass = 
            ReadBytesX( &d->EncryptedFile, 
                        InDataBuffer, 
                        BytesToDecryptThisPass );
                        
        // If the block wasn't entirely read from the encrypted file, then 
        // return with an error message.
        if( BytesReadThisPass != BytesToDecryptThisPass )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't read from encrypted file '%s'.\n", 
                        NameOfEncryptedInputFile.Value );
                    
                printf( "Tried to read %ld bytes, but actually read %ld.\n",
                        BytesToDecryptThisPass, BytesReadThisPass );
            }
            
            // Set the result code to be returned by this routine.
            Result = RESULT_CANT_READ_ENCRYPTED_FILE;
    
            // Exit, returning result to mean an error occurred.
            goto Exit;
        }
        
        // Decrypt the block of data with the block of true random key bytes
        // and the block of pseudo-random key bytes.
        for( i = 0; i < BytesToDecryptThisPass; i++ )
        {
            // XOR a pseudo-random byte derived from the password with a true 
            // random key byte from the one-time pad file to form the final key 
            // byte used for decrypting the data.
            //
            // Decrypt the current data byte by XOR'ing the final key byte, 
            // then advance the destination address by one byte.
            *InDataBuffer++ ^= 
                d->TrueRandomKeyBuffer[i] ^ 
                    GetNextByteFromPasswordHashStream( d );    
        }
 
        // Reduce the data bytes left to be decrypted by the amount done this
        // pass.
        BytesLeftToDecrypt -= BytesToDecryptThisPass;
    }
    
    // All done, skip to the exit.
    goto Exit;

////////////    
ErrorExit:// All errors come here.
////////////

    // Erase any decrypted data from the data buffer.
    ZeroBytes( DataBuffer, BytesToDecrypt );
      
///////
Exit:// Common exit from this routine.
///////

    // Erase the key bytes from the true random key buffer.
    ZeroBytes( d->TrueRandomKeyBuffer, KEY_BUFFER_SIZE );
      
    // The data buffer contains unencrypted data if there was no error.
     
    // Return the result code.
    return( Result );
}

/*------------------------------------------------------------------------------
| DecryptFileOT7
|-------------------------------------------------------------------------------
|
| PURPOSE: To decrypt an OT7 format file using one-time pad encryption.
|
| DESCRIPTION: This routine decodes an OT7 format file to produce a plaintext 
| file.
|
| The encrypted file encoding may either be binary or base64. The base64 format
| used is specified by RFC 4648.
|
| See EncryptFileOT7() for the corresponding routine that does encryption.
|
| HISTORY: 
|    03Nov13 
|    25Feb14 Added more status messages.
|    01Mar14 Added advancing the pseudo-random stream to account for the block 
|            of fill bytes generated during encryption.
|    06Mar14 Grouped local variables into OT7Context.
|    22Mar14 Factored out IdentifyDecryptionKey() and DecryptFileUsingKeyFile().
------------------------------------------------------------------------------*/
    // OUT: Status - 0 if decrypted OK, or an error code if decryption failed.
u32 //
DecryptFileOT7()
{
    static OT7Context d;
     
    // Zero the working variables and buffers used in the decryption process.
    ZeroBytes( (u8*) &d, sizeof(OT7Context) );
     
    // If the format of the encrypted file was not specified on the command 
    // line, then read the file to identify the format.
    if( EncryptedFileFormat.IsSpecified == 0 )
    {
        // Read the encrypted file to discover which encoding format was used, 
        // returning either OT7_FILE_FORMAT_BINARY (0) for binary or 
        // OT7_FILE_FORMAT_BASE64 (1) for base64, or MAX_VALUE_32BIT if there 
        // was a file access error.
        EncryptedFileFormat.Value = 
            DetectFormatOfEncryptedOT7File( NameOfEncryptedInputFile.Value );
            
        // If an error occurred while attempting to determine the format of the
        // encypted file, then go to the error exit. 
        if( EncryptedFileFormat.Value == MAX_VALUE_32BIT )
        {
            // Error message has already been printed.
            
            // Global Result code has already been set.
     
            // Exit via the error path.
            goto ErrorExit;
        }
    }
    
    //--------------------------------------------------------------------------
 
    // Open the input file for reading binary or base64 data. The "rb" option
    // causes the file to be opened read-only.
    d.Status = 
        OpenFileX( &d.EncryptedFile,
                   NameOfEncryptedInputFile.Value, 
                   EncryptedFileFormat.Value, 
                   "rb" );  

    // If unable to open the input file, then exit from this routine.
    if( d.Status == 0 )
    {
        // Error message has already been printed and the global result
        // code has been set to an error code.

        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    
    // Get the size of the encrypted file. 
    d.EncryptedFileSize = GetFileSize64( d.EncryptedFile.FileHandle );
    
    // If there was an error determining the size of the encrypted file, 
    // then print an error message and exit.
    if( d.EncryptedFileSize == MAX_VALUE_64BIT )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't get size of encrypted file '%s'.\n", 
                     NameOfEncryptedInputFile.Value );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_SEEK_IN_ENCRYPTED_FILE;
        
        // Exit via the error path.
        goto ErrorExit;
    }
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "File '%s' is %s bytes long.\n", 
                NameOfEncryptedInputFile.Value,
                ConvertIntegerToString64( d.EncryptedFileSize ) );
    }
     
    // If the size of the encrypted file is less than the minimum size of an 
    // OT7 file, then don't attempt to decrypt it.
    if( d.EncryptedFileSize < OT7_MINIMUM_VALID_FILE_SIZE )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: File '%s' is too small to decrypt.\n", 
                    NameOfEncryptedInputFile.Value );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_INVALID_ENCRYPTED_FILE_FORMAT;

        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    
    // Read in the OT7 header from the encrypted file to the Header field
    // in the decryption context.
    d.BytesRead = ReadBytesX( &d.EncryptedFile, d.Header, OT7_HEADER_SIZE );
        
    // If the header wasn't entirely read, then return with an error message.
    if( d.BytesRead != OT7_HEADER_SIZE )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read header of encrypted file '%s'.\n", 
                    NameOfEncryptedInputFile.Value );
                    
            printf( "Tried to read %ld bytes, but actually read %ld.\n",
                    (u32) OT7_HEADER_SIZE, d.BytesRead );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_READ_ENCRYPTED_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "Read header from OT7 file '%s'.\n", 
                NameOfEncryptedInputFile.Value );
        
        printf( "Header = '%s'\n",        
                 ConvertBytesToHexString( (u8*) &d.Header, OT7_HEADER_SIZE ) );
    }
    
    //--------------------------------------------------------------------------
    
    // Locate the decryption parameters based on command line input as augmented
    // by other information found in the 'key.map' file.
    IdentifyDecryptionKey( &d );
    
    // If unable to decode the header to obtain the KeyAddress, then go to the
    // error exit.
    if( Result != RESULT_OK )
    {
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    
    // If the encrypted input file is open, then close it temporarily so that
    // the routine DecryptFileUsingKeyFile() can handle positioning the file
    // pointer in the event that several key files need to be tried.
    if( d.EncryptedFile.FileHandle )
    {
        // Close the file.
        d.Status = fclose( d.EncryptedFile.FileHandle );
    
        // If Status is non-zero, then there was an error.
        if( d.Status )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( 
                    "ERROR: Can't close encrypted file '%s'.\n", 
                    NameOfEncryptedInputFile.Value );
            }

            // Set the result code to mean that the encrypted file couldn't
            // be closed.
            Result = RESULT_CANT_CLOSE_ENCRYPTED_FILE;
             
            // Go exit since something is wrong if the input file can't be
            // closed.
            goto ErrorExit;
        }

        // Mark the file as closed in the extended file handle.
        d.EncryptedFile.FileHandle = 0;
    }
    
    //--------------------------------------------------------------------------
    // TRY EACH FILE IN THE LIST OF KEY FILES UNTIL DECRYPTION SUCCEEDS.
    //--------------------------------------------------------------------------
      
    // Refer to the first item in the key file list using cursor 
    // CurrentKeyFileName.
    ToFirstItem( KeyFileNames.Value, &d.CurrentKeyFileName );
                  
    // Scan the key file name list to the end or until decryption succeeds.
    while( d.CurrentKeyFileName.TheItem )
    {
        // Refer to the file name to use for decryption.
        d.KeyFileName = (s8*) d.CurrentKeyFileName.TheItem->DataAddress;
 
        // Make an attempt to decrypt the file using the current key file. On
        // completion of this call the global Result code will indicate the
        // success or failure of the attempt.
        Result = DecryptFileUsingKeyFile( &d );
        
        // If decryption was completely or partially successful, then return 
        // after cleaning up memory.
        if( Result == RESULT_OK                         ||
            Result == RESULT_INVALID_CHECKSUM_DECRYPTED ||
            Result == RESULT_CANT_CLOSE_ENCRYPTED_FILE  ||
            Result == RESULT_CANT_CLOSE_KEY_FILE )
        {
            goto CleanUp;
        }

        // If decryption failed due to a problem with the key file, then it
        // might be possible to succeed with a different key file. 
        //
        // Try the next key file in the list if there is one.
        if( Result == RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING ||
            Result == RESULT_CANT_OPEN_KEY_FILE_FOR_READING ||
            Result == RESULT_CANT_SEEK_IN_KEY_FILE          || 
            Result == RESULT_CANT_READ_KEY_FILE             ||
            Result == RESULT_INVALID_COMPUTED_HEADER_KEY    ||
            Result == RESULT_INVALID_DECRYPTION_OUTPUT )
        {
            // Advance the item cursor to the next key file name in the list.           
            ToNextItem( &d.CurrentKeyFileName );
        }
        else // A non-recoverable error has occurred.
        {
            // Non-recoverable errors are failures related to accessing the
            // plaintext or encrypted files, such as the following:
            //     RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING
            //     RESULT_CANT_READ_ENCRYPTED_FILE
            //     RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_WRITING
            //     RESULT_CANT_WRITE_PLAINTEXT_FILE
            //     RESULT_CANT_CLOSE_PLAINTEXT_FILE
            //     RESULT_CANT_ERASE_USED_KEY_BYTES
 
            // Go clean up memory and return.
            goto CleanUp;
        }
         
    } // while( d.CurrentKeyFileName.TheItem )
       
    //--------------------------------------------------------------------------
    // At this point, the end of the list of key file names has been reached 
    // without successfully decrypting file. The last error code set will be 
    // returned when the application exits.
    //--------------------------------------------------------------------------
    
    // Skip to memory clean up since all files have already been closed.
    goto CleanUp;
    
    //==========================================================================
    
////////////
ErrorExit:// Errors come here to close any open file on exit.
////////////    

    // If the encrypted input file is open, then close it.
    if( d.EncryptedFile.FileHandle )
    {
        // Close the file.
        fclose( d.EncryptedFile.FileHandle );
    }
 
////////// 
CleanUp:// Common exit path for encryption success and failure.
////////// 
        
    // Zero all of the working variables and buffers using in the decryption
    // process.
    ZeroBytes( (u8*) &d, sizeof(OT7Context) );

    // Return the result code: RESULT_OK on success, or an error code on
    // failure. 
    return( Result );
}        
 
/*------------------------------------------------------------------------------
| DecryptFileUsingKeyFile
|-------------------------------------------------------------------------------
|
| PURPOSE: To decrypt an OT7 format file using a specified key file.
|
| DESCRIPTION: This routine makes a plaintext file from an OT7 format file,
| decrypting it with a given key file and the current application parameters.
|
| On entry to this routine the file to be decrypted is currently closed, but
| the file format has been set in EncryptedFileFormat.Value.
|
| On completion of this call the global Result code will indicate the success 
| or failure of the attempt.
|        
| The encrypted file encoding may either be binary or base64. The base64 format
| used is specified by RFC 4648.
|
| Input values in the OT7Context passed to this routine are:
|    EncryptedFileSize
|    KeyAddress
|    KeyFileName
|
| HISTORY: 
|    22Mar14 From DecryptFileOT7() and EncryptFileUsingKeyFile().
------------------------------------------------------------------------------*/
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code. Also sets the global Result to the same value.
u32 //
DecryptFileUsingKeyFile( OT7Context* d )
{
    u32 f;
    
    // Set the global result to OK, updating later if an error is encountered.
    Result = RESULT_OK;
    
    //--------------------------------------------------------------------------
 
    // Open the input file for reading binary or base64 data. The "rb" option
    // causes the file to be opened read-only.
    d->Status = OpenFileX( &d->EncryptedFile,
                           NameOfEncryptedInputFile.Value, 
                           EncryptedFileFormat.Value, 
                           "rb" );  

    // If unable to open the input file, then exit from this routine.
    if( d->Status == 0 )
    {
        // Error message has already been printed and the global result code 
        // has been set to an error code.

        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    
    // Read in the OT7 header from the encrypted file to the Header field in the 
    // decryption context.
    d->BytesRead = ReadBytesX( &d->EncryptedFile, d->Header, OT7_HEADER_SIZE );
        
    // If the header wasn't entirely read, then return with an error message.
    if( d->BytesRead != OT7_HEADER_SIZE )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read header of encrypted file '%s'.\n", 
                    NameOfEncryptedInputFile.Value );
                    
            printf( "Tried to read %ld bytes, but actually read %ld.\n",
                    (u32) OT7_HEADER_SIZE, d->BytesRead );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_READ_ENCRYPTED_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
     
    // Open the key file.
    d->KeyFileHandle = OpenKeyFile( d->KeyFileName );

    // If unable to open the one-time pad key file, then fail to decrypt.
    if( d->KeyFileHandle == 0 )
    {
        // OpenKeyFile() has already handled printing any error messages and
        // setting the result code to be returned when the application exits. 
     
        // Exit via the error path.
        goto ErrorExit;
    }

    //--------------------------------------------------------------------------
    // SEEK TO KEYADDRESS IN KEY FILE
    //--------------------------------------------------------------------------
    
    // Seek to the first byte of the decryption key in the key file.
    d->Status = SetFilePosition( d->KeyFileHandle, d->KeyAddress );
    
    // If unable to seek to the byte in the key file used for computing the
    // HeaderKey, then then report error and fail the decryption process.
    if( d->Status != 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't set file position in key file '%s'.\n", 
                    d->KeyFileName );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_SEEK_IN_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }

    //--------------------------------------------------------------------------
    // INITIALIZE PASSWORD HASH STREAM FOR COMPUTING HEADER KEY
    //--------------------------------------------------------------------------

    // If the password found to decrypt the header matches the default password 
    // and verbose mode is enabled, then report that the default password is 
    // being used.
    if( IsVerbose.Value && 
        IsMatchingStrings( Password.Value, DefaultPassword ) )
    {
        printf( "Using default password for decryption.\n" );
    }

    // Initialize a Skein1024 hash for computing the HeaderKey.
    //
    // This routine reads true random bytes from the current location in the 
    // given key file and XOR's them with the password to make a hash context 
    // that depends on both data sources.
    //
    // OUT: Result code is RESULT_OK on success, or an error code on failure.
    Result =
        InitializeHashWithTrueRandomBytesAndPassword( 
            d,  // Context of the file being decrypted.
                //
            &d->PasswordContext,
                // Hash context to be initialized.
                //
            PASSWORD_HASH_BIT_COUNT,  
                // Size of the hash to be produced in bits.
                //
            Password.Value );
                // The password string to feed into the hash context with the
                // true random bytes.

    // If the key file could not be read, then fail the decryption process.
    if( Result != RESULT_OK )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read key file '%s'.\n", d->KeyFileName );
        }

        // Set the result code to be returned by this routine.
        Result = RESULT_CANT_READ_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
        
    //--------------------------------------------------------------------------
    
    // Compute the header key hash from the password hash context. 
    Skein1024_Final( &d->PasswordContext, d->ComputedHeaderKey );
    
    // If the computed header key is different than the HeaderKey read from
    // the OT7 record, then the key file and/or the HeaderKey is invalid.
    if( IsMatchingBytes( 
            &d->Header[HEADERKEY_FIELD_OFFSET], 
            d->ComputedHeaderKey, 
            HEADERKEY_BYTE_COUNT ) == 0 )
    {
        // Set the result code to be returned by this routine.
        Result = RESULT_INVALID_COMPUTED_HEADER_KEY;
        
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "HeaderKey doesn't match key file and password.\n" );
            
            printf( "This can happen if key bytes have been erased.\n" );
            
            printf( "Can't decrypt using key file '%s'.\n", d->KeyFileName );
        }
        
        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    // At this point the correct key file for the OT7 record has probably been 
    // found. There is a vanishingly small possibility that another key file 
    // will also match the HeaderKey value, so if decryption fails using the 
    // current key file then other available key files should be tried as well.
    //--------------------------------------------------------------------------
         
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "HeaderKey matches, the right key file has been found.\n" );
    }

    //--------------------------------------------------------------------------
    // BEGIN ONE-TIME PAD DECRYPTION OF THE BODY SECTION OF THE OT7 RECORD.
    //--------------------------------------------------------------------------
        
    //--------------------------------------------------------------------------
    // INITIALIZE PASSWORD HASH STREAM FOR DECRYPTING BODY
    //--------------------------------------------------------------------------

    // Initialize a Skein1024 hash for generating the password hash stream.
    //
    // This routine reads true random bytes from the current location in the 
    // given key file and XOR's them with the password to make a hash context 
    // that depends on both data sources.
    //
    // OUT: Result code: RESULT_OK on success, or an error code on failure.
    Result =
        InitializeHashWithTrueRandomBytesAndPassword( 
            d,  // Context of the file being decrypted.
                //
            &d->PasswordContext,
                // Hash context to be initialized.
                //
            KEY_BUFFER_BIT_COUNT,  
                // Size of the hash to be produced in bits.
                //
            Password.Value );
                // The password string to feed into the hash context with the 
                // true random bytes.

    // If the key file could not be read, then return with an error message.
    if( Result != RESULT_OK )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read key file '%s'.\n", d->KeyFileName );
        }

        // Set the result code to be returned by this routine.
        Result = RESULT_CANT_READ_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    
    // Zero the number of pseudo-random key bytes available in the 
    // PseudoRandomKeyBuffer to begin with.
    d->PseudoRandomKeyBufferByteCount = 0;
  
    // Initialize the SumZ checksum context for producing a 64-bit hash value.
    Skein1024_Init( &d->SumZContext, SUMZ_HASH_BIT_COUNT );

    //--------------------------------------------------------------------------

    // Decrypt the ExtraKeyUsed and SizeBits fields.
    //
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error
    //      code.
    Result =
        DecryptFileToBuffer( 
            d,  // Context of a file in the process of being decrypted.
                //
            d->TextBuffer,
                // Address of the output buffer where decrypted data is to be 
                // written. 
                //
            (EXTRAKEYUSED_FIELD_SIZE + SIZEBITS_FIELD_SIZE) );
                // Number of bytes to decrypt.
                
    // If unable to decrypt the first 2 bytes of the body section, then fail the
    // decryption process.
    if( Result != RESULT_OK )
    {
        // DecryptFileToBuffer() has already handled printing any error 
        // messages.
    
        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
        
    // Include the decrypted bytes of ExtraKeyUsed and SizeBits fields in the 
    // SumZ checksum.
    Skein1024_Update( 
        &d->SumZContext, 
        d->TextBuffer, 
        (u32) (EXTRAKEYUSED_FIELD_SIZE + SIZEBITS_FIELD_SIZE) );

    //--------------------------------------------------------------------------

    // Get the number of extra key bytes used in addition to those used in
    // encrypting the OT7 record.
    d->ExtraKeyUsed = d->TextBuffer[0];
        
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "ExtraKeyUsed is %u bytes.\n", (u32) d->ExtraKeyUsed );
    }
        
    // If the ExtraKeyUsed value is out of bounds, then fail to decrypt the 
    // record. Valid values are 0 or 8.
    if( ((d->ExtraKeyUsed == 0) || (d->ExtraKeyUsed == 8)) == 0 )
    {
        // Print error message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "ERROR: ExtraKeyUsed value is invalid.\n" );
        }

        // Report decryption failure and exit.
        goto DecryptionInvalid;
    }
        
    //--------------------------------------------------------------------------
          
    // Get the SizeBits value which specifies sizes of the TextSize and FillSize
    // fields.
    d->SizeBits = d->TextBuffer[1];
    
    // Unpack the size of the TextSize field in bytes, a value from 0 to 8.
    d->TextSizeFieldSize = d->SizeBits & 0x0F;
    
    // If the field size for TextSize is out of bounds, then fail to decrypt 
    // the record.
    if( d->TextSizeFieldSize > 8 )
    {
        // Print error message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "ERROR: TextSizeFieldSize is too big.\n" );
        }

        // Report decryption failure and exit.
        goto DecryptionInvalid;
    }
        
    //--------------------------------------------------------------------------
    
    // Unpack the size of the FillSize field in bytes, a value from 0 to 8.
    d->FillSizeFieldSize = d->SizeBits >> 4;
    
    // If the field size for FillSize is out of bounds, then fail to decrypt the
    // record.
    if( d->FillSizeFieldSize > 8 )
    {
        // Print error message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "ERROR: FillSizeFieldSize is too big.\n" );
        }

        // Report decryption failure and exit.
        goto DecryptionInvalid;
    }
        
    //--------------------------------------------------------------------------
         
    // Decrypt the TextSize, FillSize, and FileNameSize fields.
    //
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error
    //      code.
    Result =
        DecryptFileToBuffer( 
            d,                       // Context for file being decrypted.
            d->TextBuffer,           // Output buffer.
            (d->TextSizeFieldSize +  // Number of bytes to decrypt.
             d->FillSizeFieldSize + 
             FILENAMESIZE_FIELD_SIZE) );  
                                   
    // If unable to decrypt the fields, then fail the decryption.
    if( Result != RESULT_OK )
    {
        // DecryptFileToBuffer() has already handled printing any error
        // messages.
    
        // Exit via the error path.
        goto ErrorExit;
    }
        
    // Include the unencrypted bytes of TextSize, FillSize, and FileNameSize 
    // fields in the SumZ checksum.
    Skein1024_Update( 
        &d->SumZContext, 
        d->TextBuffer, 
        (u32) (d->TextSizeFieldSize + 
               d->FillSizeFieldSize + 
               FILENAMESIZE_FIELD_SIZE) );
               
    //--------------------------------------------------------------------------
        
    // Get the TextSize field value, in LSB-to-MSB order.
    d->TextSize = 
        Get_u64_LSB_to_MSB_WithTruncation( 
            d->TextBuffer, d->TextSizeFieldSize );
             
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "TextSize is %s bytes.\n", 
                 ConvertIntegerToString64( d->TextSize ) );
    }
    
    // Get the FillSize field value, in LSB-to-MSB order.
    d->FillSize = 
        Get_u64_LSB_to_MSB_WithTruncation( 
            &d->TextBuffer[d->TextSizeFieldSize], 
            d->FillSizeFieldSize );
            
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "FillSize is %s bytes.\n", 
                 ConvertIntegerToString64( d->FillSize ) );
    }
 
    //--------------------------------------------------------------------------
        
    // Get the file name size field, in LSB-to-MSB order.
    d->FileNameSize = 
        Get_u16_LSB_to_MSB( 
            &d->TextBuffer[d->TextSizeFieldSize + d->FillSizeFieldSize] );
            
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "FileNameSize is %u bytes.\n", (u32) d->FileNameSize );
    }
 
    // If the file name size is larger than the largest valid file name, then  
    // fail the decryption process.
    if( d->FileNameSize > MAX_FILE_NAME_SIZE )
    {
        // Print error message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "ERROR: FileNameSize is too big.\n" );
        }

        // Report decryption failure and exit.
        goto DecryptionInvalid;
    }
          
    //--------------------------------------------------------------------------
        
    // Calculate the size of the body section of the OT7 record. This is the 
    // binary format size. If base64 encoding is used, then the body section 
    // will actually take up more bytes in the file. The file reader routine
    // handles any any differences due to encoding format.
    d->BodySize = 
        EXTRAKEYUSED_FIELD_SIZE +  // 1 byte
        SIZEBITS_FIELD_SIZE +      // 1 byte
        d->TextSizeFieldSize +     // 0 to 8 bytes
        d->FillSizeFieldSize +     // 0 to 8 bytes
        FILENAMESIZE_FIELD_SIZE +  // 2 bytes
        d->FileNameSize +          // 0 to MAX_FILE_NAME_SIZE bytes
        d->TextSize +              // 0 to 2^64 bytes
        d->FillSize +              // 0 to 2^64 bytes
        SUMZ_FIELD_SIZE;           // 8 bytes
                   
    // Print status message if in verbose mode. 
    if( IsVerbose.Value )
    {
        printf( "BodySize is %s bytes.\n",
                 ConvertIntegerToString64( d->BodySize ) );
    }
                   
    //--------------------------------------------------------------------------
        
    // If the computed size of the file exceeds the actual file size, then fail
    // the decryption process.
    if( (OT7_HEADER_SIZE + d->BodySize) > d->EncryptedFileSize )
    {
        // Print error message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( 
                "ERROR: Computed OT7 record size %s is more than the actual "
                "file size.\n",
                ConvertIntegerToString64( 
                    (u64) OT7_HEADER_SIZE + d->BodySize ) );
        }

        // Report decryption failure and exit.
        goto DecryptionInvalid;
    }
    
    //--------------------------------------------------------------------------
        
    // If a file name is embedded in the OT7 record, then decrypt it.
    if( d->FileNameSize )
    {
        // Decrypt the file name field.
        //
        // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an 
        //      error code.
        Result =
            DecryptFileToBuffer( 
                d,                       // Context for file being decrypted.
                (u8*) d->FileNameBuffer, // Output buffer.
                (u32) d->FileNameSize ); // Number of bytes to decrypt.
                    
        // If unable to decrypt the file name field, then fail.
        if( Result != RESULT_OK )
        {
            // DecryptFileToBuffer() has already handled printing an error
            // messages.
        
            // Exit via the error path.
            goto ErrorExit;
        }

        // Include the unencrypted bytes of the FileName field in the SumZ
        // checksum.
        Skein1024_Update( 
            &d->SumZContext, 
            (u8*) d->FileNameBuffer, 
            (u32) d->FileNameSize );
        
        // Put a zero at the end of the file name string.
        d->FileNameBuffer[d->FileNameSize] = 0;
            
        // If the decrypted file name is valid, then print it in verbose mode.
        if( IsFileNameValid( d->FileNameBuffer ) )
        {
            // Print status message if in verbose mode. 
            if( IsVerbose.Value )
            {
                printf( "Embedded file name is '%s'.\n", d->FileNameBuffer );
            }
            
            // If the name of the output file has not yet been specified, then 
            // use the embedded file name for the output file.
            if( NameOfDecryptedOutputFile.IsSpecified == 0 )
            {
                // Delete the last assigned file name string, initially being 
                // the default of "ot7d.out".
                DeleteString( NameOfDecryptedOutputFile.Value );
                
                // Assign the file name to the output file parameter, making a
                // separate string buffer so that general parameter string 
                // deallocation can be used later at application exit.
                NameOfDecryptedOutputFile.Value = 
                    DuplicateString( d->FileNameBuffer );
            }
        }
        else // File name is invalid.
        {
            // Print error message if in verbose mode. 
            if( IsVerbose.Value )
            {
                printf( "ERROR: Embedded file name is invalid.\n" );
                
                printf( "Defaulting to output file name '%s'.\n",
                         NameOfDecryptedOutputFile.Value );
            }
        }
        
        // Erase the contents of the FileNameBuffer since it is no longer
        // needed.
        ZeroBytes( (u8*) d->FileNameBuffer, MAX_FILE_NAME_SIZE );
    }
    
    //--------------------------------------------------------------------------
         
    // Open the output file to write binary data.
    d->PlaintextFile = fopen64( NameOfDecryptedOutputFile.Value, "wb" );
    
    // If there was an error opening the output file, then print an error
    // message and exit.
    if( d->PlaintextFile == 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't open file '%s' for writing plaintext.\n", 
                     NameOfDecryptedOutputFile.Value );
        }

        // Set the result code to be returned by this routine.
        Result = RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_WRITING;
        
        // Exit via the error path.
        goto ErrorExit;
    }

    //--------------------------------------------------------------------------
    // READ TEXTFILL FIELD DEINTERLEAVING TEXT AND FILL BYTES.
    //--------------------------------------------------------------------------
        
    // Start with all of the text bytes to be read from the TextFill field.
    d->TextBytesToReadInField = d->TextSize;
    
    // Start with all of the fill bytes to be read from the TextFill field.
    d->FillBytesToReadInField = d->FillSize;
    
    // Start with all of the TextFill field to be read.
    d->BytesToReadInField = d->TextSize + d->FillSize;
    
    // Start the interleave flag at 1 meaning that a plaintext byte should be 
    // read next. This flag alternates between 0 and 1 to separate fill bytes 
    // from text bytes.
    d->IsTextByteNext = 1;

    // Decrypt the TextFill field as long as bytes remain to be decrypted.
    while( d->BytesToReadInField )
    {
        // If text bytes remain to be read from the TextFill field, then
        // calculate the number to read on this pass.
        if( d->TextBytesToReadInField )
        {
            // Calculate the number of plaintext bytes to read on this pass, 
            // defaulting to the text buffer size.
            d->TextBytesToReadThisPass = TEXT_BUFFER_SIZE;

            // If there is less than a full block of plaintext left to read, 
            // then just read what is available.
            if( d->TextBytesToReadThisPass > d->TextBytesToReadInField )
            {
                d->TextBytesToReadThisPass = d->TextBytesToReadInField;
            }
        } 
        else // No text bytes remain to be read, but fill bytes may be.
        {
            // Read no text bytes this pass because there are none left.
            d->TextBytesToReadThisPass = 0;
            
            // Switch the interleave flag to 0 meaning that a fill byte 
            // should be read next. 
            d->IsTextByteNext = 0;
        } 
        
        // If fill bytes remain to be read from the TextFill field, then
        // calculate how many to read on this pass.
        if( d->FillBytesToReadInField )
        {
            // Calculate the number of fill bytes to read on this pass, 
            // defaulting to the text buffer size.
            d->FillBytesToReadThisPass = TEXT_BUFFER_SIZE;

            // If there is less than a full block of fill bytes left to read, 
            // then just read what is available.
            if( d->FillBytesToReadThisPass > d->FillBytesToReadInField )
            {
                d->FillBytesToReadThisPass = d->FillBytesToReadInField;
            }
            
            // Advance the pseudo-random stream to account for the block of fill 
            // bytes generated during encryption. 
            for( f = 0; f < d->FillBytesToReadThisPass; f++ )
            {
                GetNextByteFromPasswordHashStream(d);
            }
            
            // Zero f so that the memory location will be zero on exit from this
            // routine.
            f = 0;
        }
        else // No fill bytes remain to be read, but text bytes may be.
        {
            // Read no fill bytes this pass because there are none left.
            d->FillBytesToReadThisPass = 0;
            
            // Switch the interleave flag to 1 meaning that a text byte should 
            // be read next. 
            d->IsTextByteNext = 1;
        } 
        
        // Calculate the total number of bytes to read from the TextFill field 
        // on this pass. This can be up to twice the BLOCK_SIZE.
        d->BytesToReadThisPass = 
            d->TextBytesToReadThisPass + d->FillBytesToReadThisPass;
        
        //----------------------------------------------------------------------
        // DECRYPT A BLOCK OF TEXT AND/OR FILL BYTES.
        //----------------------------------------------------------------------

        // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an 
        //      error code.
        Result =
            DecryptFileToBuffer( 
                d,                        // Context for file being decrypted.
                d->TextFillBuffer,        // Output buffer.
                d->BytesToReadThisPass ); // Number of bytes to decrypt.
  
        // If unable to decrypt the TextFill field, then go try the next key 
        // file if any.
        if( Result != RESULT_OK )
        {
            // DecryptFileToBuffer() has already handled printing an error
            // messages.
        
            // Exit via the error path.
            goto ErrorExit;
        }
      
        // Deinterleave a block of text and/or fill bytes.
        DeinterleaveTextFillBytes( d );
  
        //----------------------------------------------------------------------
        // WRITE PLAINTEXT TO OUTPUT FILE.
        //----------------------------------------------------------------------

        // If text bytes were read from the TextFill field, then write them to 
        // the plaintext file.
        if( d->TextBytesToReadThisPass )
        {
            // Include the unencrypted text bytes in the SumZ checksum.
            Skein1024_Update( 
                &d->SumZContext, 
                d->TextBuffer, 
                d->TextBytesToReadThisPass );

            // Write the block of text bytes to the output file.
            d->BytesWritten = 
                WriteBytes( d->PlaintextFile, 
                            d->TextBuffer,
                            d->TextBytesToReadThisPass );
  
            // Erase the bytes from the text buffer.
            ZeroBytes( d->TextBuffer, d->TextBytesToReadThisPass );

            // If the plaintext block could not be written, then return with an 
            // error message.
            if( d->BytesWritten != d->TextBytesToReadThisPass )
            {
                // Print error message if verbose output is enabled.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Can't write plaintext file '%s'.\n", 
                             NameOfDecryptedOutputFile.Value );
                }
            
                // Set the result code to be returned when the application 
                // exits.
                Result = RESULT_CANT_WRITE_PLAINTEXT_FILE;
                
                // This error could be due to running out of space on the
                // volume holding the plaintext file.
                
                // Exit through the error path.
                goto ErrorExit;
            }
        } 
          
        // Reduce the text and fill left to be decrypted by the amount done this 
        // pass.
        d->BytesToReadInField -= d->BytesToReadThisPass;
        
        // Reduce the text left to be decrypted by the amount done this pass.
        d->TextBytesToReadInField -= d->TextBytesToReadThisPass;
    
        // Reduce the fill left to be decrypted by the amount done this pass.
        d->FillBytesToReadInField -= d->FillBytesToReadThisPass;
        
    } // while( d->BytesToReadInField )
        
    //--------------------------------------------------------------------------
    // DECRYPT SUMZ CHECKSUM FIELD
    //--------------------------------------------------------------------------

    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an 
    //      error code.
    Result =
        DecryptFileToBuffer( 
            d,                  // Context for file being decrypted.
            d->TextFillBuffer,  // Output buffer.
            SUMZ_FIELD_SIZE );  // Number of bytes to decrypt.

    // If unable to decrypt the checksum field, then go try the next key 
    // file if any.
    if( Result != RESULT_OK )
    {
        // DecryptFileToBuffer() has already handled printing an error
        // messages.
    
        // Exit via the error path.
        goto ErrorExit;
    }
        
    //--------------------------------------------------------------------------
    // DECRYPTION COMPLETE 
    //--------------------------------------------------------------------------
 
    // Close the output file.
    d->Status = fclose( d->PlaintextFile );
     
    // If unable to close the decrypted file properly, then return with an 
    // error message.
    if( d->Status )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't close plaintext file '%s'.\n", 
                    NameOfDecryptedOutputFile.Value );
        }
            
        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_CLOSE_PLAINTEXT_FILE;

        // Delete the plaintext file.
        remove( NameOfDecryptedOutputFile.Value );
    }
    else // Output file closed OK.
    {
        // Finish computing the final check sum value expected to be in the SumZ 
        // field. Put the result into TextBuffer.
        Skein1024_Final( &d->SumZContext, d->TextBuffer );  
        
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( 
                "Computed checksum is '%s'.\n",
                ConvertBytesToHexString( 
                    d->TextBuffer, SUMZ_FIELD_SIZE ) );
                   
            printf( 
                "Embedded checksum is '%s'.\n",
                ConvertBytesToHexString( 
                    d->TextFillBuffer, SUMZ_FIELD_SIZE ) );
        }                
         
        // If the embedded checksum matches the computed checksum, then
        // decryption was successful.
        if( IsMatchingBytes( 
                d->TextBuffer, 
                d->TextFillBuffer, 
                SUMZ_FIELD_SIZE ) )
        {
            // Set the result code to be returned when the application exits.
            Result = RESULT_OK;
        
            // Print success message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Embedded checksum is valid.\n\n" );
                
                printf( "Successful decryption of plaintext file '%s'.\n\n", 
                        NameOfDecryptedOutputFile.Value );
            }
        }
        else // Checksum didn't match.
        {
            // This means that some of the data in the plaintext file is 
            // invalid. Allow the decryption process to complete under these
            // conditions in order to recover partial data.
            Result = RESULT_INVALID_CHECKSUM_DECRYPTED;
        
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( 
                    "ERROR: The checksum embedded in '%s' is invalid.\n",
                     NameOfEncryptedInputFile.Value );
                            
                printf( 
                    "This may be due to a media failure or a "
                    "communication error.\n" );
                         
                printf( 
                    "Decrypted file '%s' has been produced with errors.\n", 
                     NameOfDecryptedOutputFile.Value );
                         
                printf( "Some data may be recoverable.\n" );
                
                // If key bytes are scheduled for erasure, then let the
                // user know that this will not happen.
                if( IsEraseUsedKeyBytes.Value )
                {
                    printf( "Used key bytes will not be erased in order to " 
                            "allow for decryption with alternate copies of " 
                            "the encrypted file.\n" );
                }
            }
        }
        
    } // Output file closed OK.
          
    //--------------------------------------------------------------------------
    // ERASE KEY BYTES - OPTIONAL
    //--------------------------------------------------------------------------
          
    // If all of the plaintext was decrypted properly and the used key bytes 
    // should be erased, then do that here.
    if( (Result == RESULT_OK) && IsEraseUsedKeyBytes.Value )
    {
        // Read the current file position to get the address of the key byte 
        // that marks the end of the span used to encrypt the OT7 record 
        d->EndingAddress = (u64) ftello64( d->KeyFileHandle );
        
        // Calculate the starting address of the first key byte that was used to 
        // produce the OT7 record. ExtraKeyUsed bytes are those bytes pulled 
        // from the key file for the purpose of randomizing the fill byte count.
        d->StartingAddress = d->KeyAddress - (u64) d->ExtraKeyUsed;
        
        // Calculate the number of key bytes used to make the OT7 record.
        d->TotalUsedBytes = d->EndingAddress - d->StartingAddress;
        
        // Erasing the key used to make the OT7 record provides forward 
        // security. Using this option means that the encrypted file can't be 
        // decrypted again using the same key file.  
        
        // Erase the used key bytes from the one-time pad file.
        d->NumberErased =
            EraseUsedKeyBytesInOneTimePad( 
                d,  // Context of a file after it has been encrypted or 
                    // decrypted, with the key file open for write access.
                    //
                d->StartingAddress,
                    // Starting address of the used key bytes to be erased. 
                    // This is a byte offset from the beginning of the file. 
                    //
                d->TotalUsedBytes );
                    // Size of the used key to be erased in bytes.

        // If all of the used bytes have been erased, then report that in
        // verbose mode.
        if( d->NumberErased == d->TotalUsedBytes )
        {
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Key bytes have been erased after use.\n" );
            }
        }
        else // Some of the used bytes are not erased, so exit with an error
             // message.
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't erase key bytes in file '%s'.\n", 
                         d->KeyFileName );
            }
            
            // Set the error code to be returned so that caller will know that 
            // key bytes were not erased.
            Result = RESULT_CANT_ERASE_USED_KEY_BYTES;
    
            // Exit via the error path.
            goto ErrorExit;
        }
    }
         
    //--------------------------------------------------------------------------
    // SUCCESSFUL COMPLETION OF DECRYPTION.   
    //--------------------------------------------------------------------------
 
    // Go to the common exit path used by success and failure.
    goto Exit;
    
    //==========================================================================
         
////////////////////
DecryptionInvalid:// Come here if an invalid decryption is detected.
////////////////////

    // Print error message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "ERROR: Invalid decryption using key file '%s'.\n", 
                d->KeyFileName );
    }

    // Set the result code to be returned when the application exits.
    Result = RESULT_INVALID_DECRYPTION_OUTPUT;
           
////////////
ErrorExit:// All errors come here.
////////////

    // If the output file is open, then close and delete it.
    if( d->PlaintextFile )
    {
        // Close the partial plaintext file.
        fclose( d->PlaintextFile );
        
        // Zero the file handle to indicate that the file is closed.
        d->PlaintextFile = 0;
        
        // Delete the plaintext file.
        remove( NameOfDecryptedOutputFile.Value );
    }
 
///////
Exit:// Common exit path for success and failure.
///////

    // Close the key file if it is open.
    if( d->KeyFileHandle )
    {
        // Close the key file.
        d->Status = fclose( d->KeyFileHandle );
        
        // If Status is non-zero, then there was an error.
        if( d->Status )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( 
                    "ERROR: Can't close key file '%s'.\n", 
                    d->KeyFileName );
            }

            // If the result code hasn't yet been set to an error code, then set
            // it here.
            if( Result == RESULT_OK )
            {
                Result = RESULT_CANT_CLOSE_KEY_FILE;
            }
        }
        
        // Zero the file handle to indicate that the file is closed.
        d->KeyFileHandle = 0;
    }

    // If the encrypted input file is open, then close it.
    if( d->EncryptedFile.FileHandle )
    {
        // Close the file.
        d->Status = CloseFileAfterReadingX( &d->EncryptedFile );
    
        // If Status is non-zero, then there was an error.
        if( d->Status )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't close encrypted file '%s'.\n", 
                        NameOfEncryptedInputFile.Value );
            }

            // If the result code hasn't yet been set to an error code, then set
            // it here.
            if( Result == RESULT_OK )
            {
                Result = RESULT_CANT_CLOSE_ENCRYPTED_FILE;
            }
        }
    }
    
    //--------------------------------------------------------------------------

    // Clear all the buffers used by this routine in the OT7Context record.
    ZeroBytes( d->ComputedHeaderKey, HEADERKEY_BYTE_COUNT );
    ZeroBytes( (u8*) &d->EncryptedFile, sizeof( FILEX ) );
    ZeroBytes( (u8*) d->FileNameBuffer, MAX_FILE_NAME_SIZE );
    ZeroBytes( d->FillBuffer, FILL_BUFFER_SIZE );
    ZeroBytes( d->Header, OT7_HEADER_SIZE );
    ZeroBytes( d->KeyIDHash128bit, KEYIDHASH128BIT_BYTE_COUNT );
    ZeroBytes( (u8*) &d->PasswordContext, sizeof( Skein1024Context ) );
    ZeroBytes( d->PseudoRandomKeyBuffer, KEY_BUFFER_SIZE );
    ZeroBytes( (u8*) &d->SumZContext, sizeof( Skein1024Context ) );
    ZeroBytes( d->TextBuffer, TEXT_BUFFER_SIZE );
    ZeroBytes( d->TextFillBuffer, TEXTFILL_BUFFER_SIZE );
    
    // Clear all the working variables in the OT7Context record used by this 
    // routine.
    d->BodySize = 0;
    d->BytesRead = 0;
    d->BytesWritten = 0;
    d->BytesToReadInField = 0;
    d->BytesToReadThisPass = 0;
    // d->EncryptedFileSize is an input value kept for use with other key files.
    d->EndingAddress = 0;
    d->ExtraKeyUsed = 0;
    d->FileNameSize = 0;
    d->FillBytesToReadInField = 0;
    d->FillBytesToReadThisPass = 0;
    d->FillSize = 0;
    d->FillSizeFieldSize = 0;
    d->IsTextByteNext = 0;
    // d->KeyAddress is an input value kept for use with other key files.
    d->KeyFileHandle = 0;
    d->KeyFileName = 0;
    d->NumberErased = 0;
    d->PlaintextFile = 0;
    d->PseudoRandomKeyBufferByteCount = 0;
    d->SizeBits = 0;
    d->StartingAddress = 0;    
    d->Status = 0;
    d->TextBytesToReadInField = 0;
    d->TextBytesToReadThisPass = 0;
    d->TextSize = 0;
    d->TextSizeFieldSize = 0;
    d->TotalUsedBytes = 0;
     
    //--------------------------------------------------------------------------
    // Return the result code RESULT_OK if the encryption process was 
    // successful. Any other code indicates that an error occurred which may or 
    // may not be recoverable using a different key file.  
    return( Result );
}

/*------------------------------------------------------------------------------
| DeinterleaveTextFillBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To deinterleave text and fill bytes from the TextFillBuffer.
|
| DESCRIPTION: This routine manages the ordering of bytes being read from the
| TextFill field of an OT7 record.
|
| The destination of the text bytes is the TextBuffer of the given OT7Context 
| record. The FillBuffer is not used because the fill bytes are not needed for 
| decryption.  
|
| The source is the TextFillBuffer in the same context record.
|
| The number and ordering of bytes to be interleaved depends on the current
| state of the context record.
|
| Note that bytes are erased from the TextFillBuffer after they have been moved
| to the TextBuffer or accounted for as being fill bytes.
|
| See also InterleaveTextFillBytes() which is somewhat the reverse of this 
| routine.
|
| HISTORY: 
|    16Mar14 From InterleaveTextFillBytes().
------------------------------------------------------------------------------*/
void
DeinterleaveTextFillBytes( OT7Context* d )
{
    u32 i;
    u32 t;
    u32 f;
            
    // Start with no text bytes deinterleaved by setting t to 0.
    t = 0;

    // Start with no fill bytes deinterleaved by setting f to 0.
    f = 0;
        
    // Deinterleave a block of text and/or fill bytes.
    for( i = 0; i < d->BytesToReadThisPass; i++ )
    {
        // If a text byte should be fetched next from the TextFill buffer, and 
        // text bytes remain to be encrypted, then move one text byte.
        if( d->IsTextByteNext && (t < d->TextBytesToReadThisPass) )
        {
            // Copy one byte from the TextFillBuffer to the TextBuffer.
            d->TextBuffer[t] = d->TextFillBuffer[i];
                    
            // Account for moving the text byte by incrementing t.
            t++;
                
            // If fill bytes remain to be moved, then select a fill byte next.
            if( f < d->FillBytesToReadThisPass )
            {
                d->IsTextByteNext = 0;
            }
        } 
        else // A fill byte should be fetched next.
        {
            // We don't need to do anything here with a fill byte when 
            // decrypting.
             
            // Account for the fill byte by incrementing f.
            f++;
            
            // If text bytes remain to be deinterleaved, then select a text 
            // byte next.
            if( t < d->TextBytesToReadThisPass )
            {
                d->IsTextByteNext = 1;
            }
        }
        
        // Erase the byte from the TextFillBuffer.
        d->TextFillBuffer[i] = 0;
    }
    
    // Clean up by clearing local variables.
    i = 0;
    t = 0;
    f = 0;
}

/*------------------------------------------------------------------------------
| DeleteEmptyStringsInStringList
|-------------------------------------------------------------------------------
|
| PURPOSE: To delete each item in a list that refers to an empty string.
|
| DESCRIPTION: The input list refers to dynamically allocated strings. If the
| string is empty, then the string buffer and the Item record that refer to it
| are deallocated.
|           
| HISTORY: 
|    24Nov13 From StripComments().
|    28Feb14 Replaced unused BufferAddress with DataAddress, revising the code
|            in this routine.
------------------------------------------------------------------------------*/
void
DeleteEmptyStringsInStringList( List* L ) // A list of strings.
{
    Item*    Next;
    ThatItem C;
     
    // Refer to the list as the current list.
    ToFirstItem( L, &C );
    
    // For each item in the list.
    while( C.TheItem )
    {
        // If the current item refers to an empty string, then extract the
        // item from the list and delete it, also deallocating the string
        // buffer.
        if( CountString( (s8*) C.TheItem->DataAddress ) == 0 )
        {
            // Track the next item.
            Next = C.TheItem->NextItem;
            
            // If there is a dynamically allocated buffer attached to the 
            // Item, then deallocate it.
            if( C.TheItem->DataAddress )
            {
                // Deallocate the string buffer.
                free( C.TheItem->DataAddress );
            }
            
            // Extract the current item from the list and delete it.
            DeleteItem( ExtractTheItem( &C ) );
            
            // Make the next item the current one.
            C.TheItem = Next;
        }
        else // Current line is not empty.
        {
            // Advance to the next item in the list.
            ToNextItem(&C);
        }
    }
}

/*------------------------------------------------------------------------------
| DeleteItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To deallocate an Item record that isn't part of a list.
|
| DESCRIPTION: Before an item can be deleted it must first be extracted from the 
| list that holds it.  
|
| ASSUMES: Item is not currently inserted in a list.
|
| HISTORY:  
|    17Nov13 Revised to use free().
|    26Jan14 Changed to zero Item buffer before deallocating it.
------------------------------------------------------------------------------*/
void
DeleteItem( Item* AnItem )
{
    // If an Item record is supplied, then delete it.
    if( AnItem )
    {
        // Fill the Item buffer with zero bytes.
        ZeroBytes( (u8*) AnItem, sizeof( Item ) );
        
        // Free the record back to the pool it came from.
        free( AnItem );
     
        // Account for the Item record which is no longer in use.
        CountOfItemsInUse--;
    }
}

/*------------------------------------------------------------------------------
| DeleteItems
|-------------------------------------------------------------------------------
|
| PURPOSE: To deallocate a series of Item records that have been extracted from 
|          a list. 
|
| DESCRIPTION: Before items can be deleted they must first be extracted from the 
| list that holds them: see ExtractItems().
|
| HISTORY: 
|    17Nov13 Revised to use free().
------------------------------------------------------------------------------*/
void
DeleteItems( Item* First )
{
    Item* A;

    // Until the last Item record has been freed.
    while( First )
    {
        // Save the address of the current Item in A.
        A = First;
        
        // Follow the link to the next item, making it first.
        First = A->NextItem;
        
        // Free the current Item record back to the general memory pool.
        DeleteItem( A );
    }
}       

/*------------------------------------------------------------------------------
| DeleteList
|-------------------------------------------------------------------------------
|
| PURPOSE: To delete items in a list and deallocate the list control block.
|
| DESCRIPTION: Use this routine to deallocate lists made using MakeList().
|
| HISTORY: 
|    17Nov13 Revised to use free().
|    26Jan14 Revised to zero the List record before deallocating it.
------------------------------------------------------------------------------*/
void
DeleteList( List* L )
{
    // If a list record is supplied, then deallocate it along with any items
    // in the list.
    if( L )
    {
        // If there are any items in the list, delete them.
        if( L->ItemCount )
        {
            EmptyList( L );
        }
        
        // Fill the List record with zero bytes.
        ZeroBytes( (u8*) L, sizeof(List) );
         
        // Free the List record back to the pool it came from.
        free( L );
     
        // Account for the list record no longer in use.
        CountOfListsInUse--;
    }
}

/*------------------------------------------------------------------------------
| DeleteListOfDynamicData
|-------------------------------------------------------------------------------
|
| PURPOSE: To delete a list of items and their associated dynamically allocated 
|          data buffers.
|
| DESCRIPTION: If all of the data in the given list is held in individually
| allocated buffers then this procedure can be used to free the list and data 
| buffers in a single procedure call.
|
| EXAMPLE:  DeleteListOfDynamicData(L);
|
| ASSUMES: 
|
|    If the buffer address field of an Item is non-zero, then it refers to a 
|    dynamically-allocated segment of memory.
|
|    If the buffer address field is zero then the data address field refer to 
|    a dynamically allocated segment of memory.
|
|    The buffer was allocated using malloc().
|
| HISTORY: 
|    03Apr89
|    23Oct89 removed tree capability
|    03Oct91 Revised for Focus. Name changed from 'DeleteListOfDynamicStrings'.
|    18Nov93 changed to call 'DeleteList'.
|    10Dec96 changed to free the 'BufferAddress' instead of 'DataAddress'.
|    28Dec01 Deallocate user data buffers to the OS memory pool.
|    01Dec13 Revised to use free().
|    28Feb14 Removed unused BufferAddress field from Item record and code from
|            this routine.
------------------------------------------------------------------------------*/
void
DeleteListOfDynamicData(List* L)
{
    ThatItem C;

    // Refer to the first item in the list using cursor C.
    ToFirstItem( L, &C ); 
    
    // Free the data attached to each item in the list.
    while( C.TheItem )    
    {
        // If the address of a dynamically allocated buffer is associated with 
        // the item, then free that buffer.
        if( C.TheItem->DataAddress )
        {
            free( C.TheItem->DataAddress );
        }
         
        // Advance the item cursor to the next item in the list.           
        ToNextItem(&C);
    }
 
    // Then free the list and item records.
    DeleteList(L); 
}

/*------------------------------------------------------------------------------
| DeleteString
|-------------------------------------------------------------------------------
|
| PURPOSE: To deallocate a string buffer after filling it with zero bytes.
|
| DESCRIPTION: Fills all of the bytes prior to the first zero byte with zero
| bytes, and then frees it.
|           
| HISTORY: 
|    26Jan14  
------------------------------------------------------------------------------*/
void
DeleteString( s8* S )
{
    // If a valid string address has been given, then zero and free it.
    if( S )
    {
        // Fill the string buffer with zero bytes to avoid leaking information
        // to a virtual memory page file if there is one.
        ZeroFillString( S );
        
        // Return the string buffer to the dynamical memory pool.
        free( S );
    }
}

/*------------------------------------------------------------------------------
| DetectFormatOfEncryptedOT7File
|-------------------------------------------------------------------------------
| 
| PURPOSE: To read an OT7-encrypted file to discover which encoding format was 
|          used.
|
| DESCRIPTION: Returns either OT7_FILE_FORMAT_BINARY (0) for binary or 
| OT7_FILE_FORMAT_BASE64 (1) for base64, or MAX_VALUE_32BIT if an error 
| occurred.
|
| On error, global Result is set to the error code.
|
| HISTORY: 
|    03Nov13 
|    08Mar14 Revised to use a dedicated local buffer instead of a shared global
|            buffer. Added clearing the buffer after use.
------------------------------------------------------------------------------*/
     // OUT: File format code, or MAX_VALUE_32BIT if an error occurred.
u32  //
DetectFormatOfEncryptedOT7File( s8* FileName )
{
    u8 c;
    u32 i;
    FILE* F;
    static u8 Buffer[TEXT_BUFFER_SIZE];
    u32 BytesRead;
    u32 BytesToRead;
    u64 FileSize;
    u32 Format;
    
    // Set the default format to mean undefined: MAX_VALUE_32BIT (0xFFFFFFFF).
    // This will be returned if unable to detect the file format.
    Format = MAX_VALUE_32BIT;
      
    // Start with the file handle set to zero.
    F = 0;
 
    // Open the file using the standard file open command.
    F = fopen64( FileName, "rb" );
    
    // If unable to open the input file, then print an error message and 
    // return.
    if( F == 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't open input file '%s' for reading.\n", 
                    FileName );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING;
 
        // Go clear the buffer and exit with the default format code.
        goto Exit;
    }
    
    // Get the size of the file in bytes, or MAX_VALUE_64BIT if there was
    // an error.
    FileSize = GetFileSize64( F );
    
    // If there was an error determining the file size, then set the error
    // code and print a message.
    if( FileSize == MAX_VALUE_64BIT )
    {
        // Close the file.
        fclose( F );
        
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't set file position in file '%s'.\n", 
                     FileName );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_SEEK_IN_ENCRYPTED_FILE;
     
        // Go clear the buffer and exit with the default format code.
        goto Exit;
    }
    
    // Default to reading as many bytes will fit into the TextBuffer.
    BytesToRead = TEXT_BUFFER_SIZE;
    
    // If the file is smaller than the TextBuffer, then just read however
    // many bytes are available.
    if( FileSize < (u64) TEXT_BUFFER_SIZE )
    {
        BytesToRead = (u32) FileSize;
    }

    // Read a block of text bytes to the TextBuffer.
    BytesRead = ReadBytes( F, (u8*) Buffer, BytesToRead );
                           
    // Close the encrypted file after reading the block.
    fclose( F );
                           
    // If unable to read from the file, then print an error message and
    // return.
    if( BytesRead != BytesToRead )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read file '%s'.\n", FileName );
        }
    
        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_READ_ENCRYPTED_FILE;
 
        // Go clear the buffer and exit with the default format code.
        goto Exit;
    }
     
    // Test the block of data read to see if it is only base64 or whitespace.
    for( i = 0; i < BytesRead; i++ )
    {
        // Get a character from the input buffer.
        c = Buffer[i];
         
        // If the current byte in the block is not in the base64 alphabet
        // and also is not a whitespace character, then classify the file
        // format as binary.
        if(  !( IsBase64(c) || IsWhiteSpace(c) ) )
        {
            // Set the file format to binary.
            Format = OT7_FILE_FORMAT_BINARY;
            
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Detected OT7 record format is binary.\n" );
            }
            
            // Go clear the buffer and return the format code.
            goto Exit; 
        }
    }
    
    // The whole block is base64, so conclude that the file is in base64
    // format. It is highly unlikely that a whole block of encrypted 
    // binary data just happens to fall in the base64 range, so this is
    // probably a safe bet.
    Format = OT7_FILE_FORMAT_BASE64;
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "Detected OT7 record format is base64.\n" );
    }

///////    
Exit://
///////

    // Zero the buffer.
    ZeroBytes( (u8*) Buffer, TEXT_BUFFER_SIZE );
    
    // Return the format code or MAX_VALUE_32BIT (0xFFFFFFFF) on error.
    return( Format );
}

/*------------------------------------------------------------------------------
| DuplicateString
|-------------------------------------------------------------------------------
|
| PURPOSE: To make a copy of a string, dynamically allocating a new buffer.
|
| DESCRIPTION:  
|
| EXAMPLE:           S = DuplicateString( "Some string" );
|  
| HISTORY: 
|    30Jan89 
|    15Feb93 changed to use AllocateString.
|    25Nov13 Replaced CountString() with strlen() and AllocateString() with
|            malloc(). Handled out-of-memory condition.
------------------------------------------------------------------------------*/
    // OUT: The address of the new string, or 0 if unable to allocate a new
    //      string.
s8* //
DuplicateString( s8* AString )
{
    s8* NewString;
    u32 LengthOfString;
    
    // Measure the length of the string, not counting the zero terminator byte.
    LengthOfString = strlen(AString); 
    
    // Allocate a new buffer for the string and the zero terminator byte.
    NewString = malloc( LengthOfString + 1 );

    // If the buffer was allocated, then copy the string there.
    if( NewString )
    {
        // Copy the bytes to the new buffer including the zero terminator byte.
        CopyBytes( (u8*) AString, 
                   (u8*) NewString, 
                   (s32) LengthOfString + 1 );
    }
    
    // Return the address of the new string, or 0 if unable to allocate a new
    // string.
    return( NewString );
}

/*------------------------------------------------------------------------------
| EmptyList
|-------------------------------------------------------------------------------
|
| PURPOSE: To delete items in a list, but keep the list control block itself.
|
| DESCRIPTION:
|
| HISTORY: 
|    17Nov13 Revised comments.
------------------------------------------------------------------------------*/
void
EmptyList( List* L )
{
    Item* FirstItem;
 
    // If the list is already empty, just return.
    if( L->ItemCount == 0 ) 
    {   
        return;
    }
    
    // Refer to the first Item record in the list.
    FirstItem = L->FirstItem;
    
    // Extract all the Item records from the list.
    ExtractItems( L, FirstItem, L->ItemCount );
    
    // Free the Item records back to the pool.
    DeleteItems( FirstItem );
}

/*------------------------------------------------------------------------------
| ExtractItems
|-------------------------------------------------------------------------------
|
| PURPOSE: To extract a series of items from a list but leave them connected to 
|          one another.
|
| DESCRIPTION: 
|
| ASSUMES: The specified number of items can be extracted.
|           
| HISTORY: 
|    17Jun97 
------------------------------------------------------------------------------*/
void
ExtractItems( List* L, 
                        // The list holding the items to be extracted.
                        //
              Item* FromItem, 
                          // First item to be extracted from the list.
                          //
              u32   ItemCount )
                          // Number of items to be extracted from the list.
{
    u32   i;
    Item* LastFromItem;
    Item* PrvItem;
    Item* NxtItem;
 
    // Locate the address of the last item to be extracted.
    LastFromItem = FromItem;
    for( i = 1; i < ItemCount; i++ )
    {
        LastFromItem = LastFromItem->NextItem;
    }
    
    // Refer to the item before the first item.
    PrvItem = FromItem->PriorItem;
    
    // Refer to the item after the last item.
    NxtItem = LastFromItem->NextItem;

    // If the FromItem is first.
    if( L->FirstItem == FromItem )
    {
        // Revise the first item link.
        L->FirstItem = NxtItem; // May be zero.
    }
    
    // If the LastFromItem is last.
    if( L->LastItem == LastFromItem )
    {
        // Revise the last item link.
        L->LastItem = PrvItem;  // May be zero.
    }
    
    // Patch forward link if there is one.
    if( PrvItem )
    {
        PrvItem->NextItem = NxtItem;
    }
    
    // Patch backward link if there is one.
    if( NxtItem )
    {
        NxtItem->PriorItem = PrvItem;
    }
    
    // Account for the extracted items.
    L->ItemCount -= ItemCount;
    
    // Clear the links at the ends of the extracted series.
    FromItem->PriorItem = 0;
    LastFromItem->NextItem = 0;
}

/*------------------------------------------------------------------------------
| ExtractTheItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To extract the current item from the current list.
|
| DESCRIPTION: The current item is extracted and the ThatItem cursor is adjusted 
| to refer to the prior item if there is one or the next one if there is no 
| prior item.
|
| If the item being extracted is the last one in the list then C.TheItem is set 
| to the prior item.
|
| EXAMPLE:  AnItem = ExtractTheItem(&C);
|
| ASSUMES: Direction through list is first-to-last.
|
| HISTORY: 
|    06Jan88
|    07Sep89 added 0 item protection
|    04Oct91 Revised for Focus.
|    26Nov91 revised to reset TheItem
|    01Dec91 IsItemAlone TheItem reset
|    25Oct93 removed MarkItemAsNotInserted
|    28Oct93 upgrade from Focus.
|    06Jan02 Revised to use ThatItem.
|    26Nov13 Revised comments.
------------------------------------------------------------------------------*/
        // OUT: The address of the item extracted or zero if there is no 
Item*   //      current item.
ExtractTheItem( ThatItem* C )
{
    Item* PrvItem;
    Item* NxtItem;
    Item* XItem;
    List* L;
     
    // If there is no current list or item.
    if( ( C == 0 )          || 
        ( C->TheList == 0 ) || 
        ( C->TheItem == 0 ) )
    {
        // Just return zero.
        return(0);
    }
    
    // Refer to the current list.
    L = C->TheList;
    
    // Refer to the item being extracted.
    XItem = C->TheItem;  

    // Refer to the item prior to the current item.
    PrvItem = C->TheItem->PriorItem;
    
    // Refer to the item after the current item.
    NxtItem = C->TheItem->NextItem;
    
    // Decrement the list item count.
    L->ItemCount--;
    
    // If there is only one item in the list.
    if( IsItemAlone(XItem) )
    {
        // Mark the list as having no items.
        MarkListAsEmpty( L );
        
        // Mark the current item as missing.
        C->TheItem = 0;
    }
    else // The item is connect to other items.
    {
        // If the current item is first in the list.
        if( IsItemFirst(XItem) )
        {
            // Mark next item as first.
            MarkItemAsFirst(NxtItem);   
            
            // Make the first item of the list the one following the current 
            // item.
            L->FirstItem = NxtItem; 
                
            // Make the next item the current one.
            C->TheItem = NxtItem; 
        }
        else // Not the first item.
        {
            // If the item is last.
            if( IsItemLast(XItem) )
            {
                // Mark previous item as last.
                MarkItemAsLast(PrvItem);
                 
                // Make the last item of the list the one prior to the current 
                // item.
                L->LastItem = PrvItem;
                   
                // Make the prior item the current one.
                C->TheItem = PrvItem; 
            }
            else // The current item is somewhere in the middle of the list.
            {
                // Relink neighboring items together, bypassing the current 
                // item.
                NxtItem->PriorItem = PrvItem;
                PrvItem->NextItem  = NxtItem;
                
                // Make the prior item the current one.
                C->TheItem = PrvItem; 
            }
        }
    }
    
    // Return the address of the item that was extracted.
    return(XItem);
}

/*------------------------------------------------------------------------------
| EncryptBufferToFile
|-------------------------------------------------------------------------------
|
| PURPOSE: To encrypt data from a buffer to a file. 
|
| DESCRIPTION: Encrypts the buffer in blocks defined by KEY_BUFFER_SIZE. 
|
| Uses TrueRandomKeyBuffer[] to store key bytes read from the one-time pad file.
|
| Uses names of the one time pad file and the encrypted file to report error
| messages, KeyFileName, and NameOfEncryptedOutputFile.
|
| HISTORY: 
|    02Nov13 
|    17Feb14 Added password-derived key encryption.
|    27Feb14 Revised to generate uniform blocks of pseudo-random data, buffering
|            the unused portion between calls to this routine.
|    28Feb14 Removed hash size change on finalization. Factored out
|            GetNextByteFromPasswordHashStream(). Removed zeroing of the
|            PseudoRandomKeyBuffer[] since it needs to persist between calls to
|            this routine.
|    16Mar14 Revised to use OT7Context record.
------------------------------------------------------------------------------*/
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.
u32 //
EncryptBufferToFile( 
    OT7Context* e,
                // Context of a file in the process of being encrypted.
                //
    u8*    DataBuffer,
                // Address of data to be encrypted.
                //
    u32    BytesToEncrypt )
                // Number of bytes to encrypt.
{
    u32 i;
    u32 Result;
    u32 BytesRead;
    u32 BytesToEncryptThisPass;
    u32 BytesWrittenThisPass;
    
    // Start with no errors detected.
    Result = RESULT_OK;
     
    // Encrypt as long as bytes remain to be encrypted.
    while( BytesToEncrypt )
    {
        // Calculate the number of bytes to write on this pass, defaulting to 
        // the key buffer size.
        BytesToEncryptThisPass = KEY_BUFFER_SIZE;

        // If there is less than a full block left to write, then just write
        // what is available.
        if( BytesToEncryptThisPass > BytesToEncrypt )
        {
            BytesToEncryptThisPass = BytesToEncrypt;
        }
  
        // Read a block of bytes to the TrueRandomKeyBuffer.
        BytesRead = ReadBytes( e->KeyFileHandle, 
                               e->TrueRandomKeyBuffer,
                               BytesToEncryptThisPass );

        // If the one-time pad file could not be read, then return with an 
        // error message.
        if( BytesRead != BytesToEncryptThisPass )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't read key file '%s'.\n", 
                         e->KeyFileName );
            }

            // Set the result code to be returned by this routine.
            Result = RESULT_CANT_READ_KEY_FILE;
    
            // Exit, returning result to mean an error occurred.
            goto Exit;
        }
        
        // Encrypt the block of data with the block of true random key bytes
        // and the block of pseudo-random key bytes.
        for( i = 0; i < BytesToEncryptThisPass; i++ )
        {
            // XOR a pseudo-random byte derived from the password with a true 
            // random key byte from the one-time pad file to form the final key 
            // byte used for encrypting the data.
            e->TrueRandomKeyBuffer[i] ^= GetNextByteFromPasswordHashStream(e);
                
            // Encrypt the current data byte by XOR'ing it with the current key 
            // byte, then advance the data source address by one byte.
            e->TrueRandomKeyBuffer[i] ^= *DataBuffer++; 
        }

        // Write the encrypted data bytes to the encrypted file.
        BytesWrittenThisPass = 
            WriteBytesX( &e->EncryptedFile, 
                         e->TrueRandomKeyBuffer, 
                         BytesToEncryptThisPass );

        // If the block wasn't entirely written to the encrypted file, then 
        // return with an error message.
        if( BytesWrittenThisPass != BytesToEncryptThisPass )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't to write to encrypted file '%s'.\n", 
                        NameOfEncryptedOutputFile.Value );
                    
                printf( "Tried to write %ld bytes, but actually wrote %ld.\n",
                        BytesToEncryptThisPass, BytesWrittenThisPass );
            }
            
            // Set the result code to be returned by this routine.
            Result = RESULT_CANT_WRITE_ENCRYPTED_FILE;
    
            // Exit, returning result to mean an error occurred.
            goto Exit;
        }

        // Reduce the data bytes left to be encrypted by the amount done 
        // this pass.
        BytesToEncrypt -= BytesToEncryptThisPass;
    }

///////
Exit://
///////

    // The data buffer has not been modified, it still contains unencrypted 
    // data.
    //
    // TrueRandomKeyBuffer[] contains no key bytes, only encrypted data at this 
    // point.
    //
    // PseudoRandomKeyBuffer[] may contain key bytes. Leave them for later 
    // cleanup.
    
    // Zero the true-random key buffer.
    ZeroBytes( e->TrueRandomKeyBuffer, KEY_BUFFER_SIZE );
      
    // Return the result code.
    return( Result );
}

/*------------------------------------------------------------------------------
| EncryptFileOT7
|-------------------------------------------------------------------------------
|
| PURPOSE: To encrypt a plaintext file using one-time pad encryption.
|
| DESCRIPTION: This routine makes an OT7-format file from a plaintext file.
|
| The plaintext file is treated as binary data for purposes of encryption, so
| any type of file can be encrypted.
|
| The encrypted OT7-format file can be generated in binary or base64 format.
| The specification for base64 encoding is RFC 4648.
|
| HISTORY: 
|    29Sep13 
|    16Oct13 Added option to specify the number of fill bytes.
|    08Feb14 Added SizeBits field and made TextSize and FillSize be variable
|            length fields.
|    21Feb14 Fixed support for '-nofilename' option.
|    25Feb14 Added handling of GetFileSize64() errors.
|    28Feb14 Revised fill byte generator to use 
|            GetNextByteFromPasswordHashStream().
|    08Mar14 Revised to use OT7Context record instead of separate local 
|            variables. Factored out IdentifyEncryptionKey().
|    15Mar14 Factored out EncryptFileUsingKeyFile() to make loop easier to 
|            follow. 
------------------------------------------------------------------------------*/
    // OUT: Status - RESULT_OK if encrypted OK, or an error code if encryption 
    //      failed. The global result code Result contains the same value.
u32 //
EncryptFileOT7()
{
    static OT7Context e;
    
    // Zero all of the working variables and buffers using in the encryption
    // process.
    ZeroBytes( (u8*) &e, sizeof(OT7Context) );
     
    // Locate the encryption parameters based on command line input as augmented
    // by other information found in the 'key.map' file.
    IdentifyEncryptionKey( &e );
        
    //--------------------------------------------------------------------------
    // TRY EACH FILE IN THE LIST OF KEY FILES UNTIL ENCRYPTION SUCCEEDS.
    //--------------------------------------------------------------------------
    
    // Refer to the first item in the key file list using cursor 
    // CurrentKeyFileName.
    ToFirstItem( KeyFileNames.Value, &e.CurrentKeyFileName ); 
    
    // Scan the key file name list to the end or until encryption succeeds.
    while( e.CurrentKeyFileName.TheItem )    
    {
        // Refer to the current key file name.
        e.KeyFileName = (s8*) e.CurrentKeyFileName.TheItem->DataAddress;
        
        // Make an attempt to encrypt the file using the current key file. On
        // completion of this call the global Result code will indicate the
        // success or failure of the attempt.
        Result = EncryptFileUsingKeyFile( &e );
        
        // If encryption was successful, then return after cleaning up memory.
        if( Result == RESULT_OK )
        {
            goto CleanUp;
        }
         
        // If encryption failed due to a problem with the key file, then it
        // might be possible to succeed with a different key file. 
        //
        // Try the next key file in the list if there is one.
        if( Result == RESULT_CANT_OPEN_KEY_FILE_FOR_READING ||
            Result == RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING ||
            Result == RESULT_CANT_SEEK_IN_KEY_FILE          ||
            Result == RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD ||
            Result == RESULT_CANT_READ_KEY_FILE             ||
            Result == RESULT_CANT_ERASE_USED_KEY_BYTES      ||
            Result == RESULT_CANT_CLOSE_KEY_FILE )
        {
            // Advance the item cursor to the next key file name in the list.           
            ToNextItem( &e.CurrentKeyFileName );
        }
        else // A non-recoverable error has occurred.
        {
            // Non-recoverable errors are failures related to accessing the
            // plaintext or encrypted files, such as the following:
            //     RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_READING
            //     RESULT_CANT_SEEK_IN_PLAINTEXT_FILE
            //     RESULT_CANT_READ_PLAINTEXT_FILE
            //     RESULT_CANT_CLOSE_PLAINTEXT_FILE
            //     RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_WRITING
            //     RESULT_CANT_WRITE_ENCRYPTED_FILE
            //     RESULT_CANT_CLOSE_ENCRYPTED_FILE
 
            // Go clean up memory and return.
            goto CleanUp;
        }
        
    } // while( e.CurrentKeyFileName.TheItem )
       
    //--------------------------------------------------------------------------
    // At this point, the end of the list of key file names has been reached 
    // without successfully encrypting the plaintext file. Drop through to the 
    // exit. The last error code set will be returned when the application 
    // exits.
    //--------------------------------------------------------------------------
    
////////// 
CleanUp:// Common exit path for encryption success and failure.
////////// 
        
    // Zero all of the working variables and buffers using in the encryption
    // process.
    ZeroBytes( (u8*) &e, sizeof(OT7Context) );

    // Return the result code: RESULT_OK on success, or an error code on
    // failure. 
    return( Result );
}

/*------------------------------------------------------------------------------
| EncryptFileUsingKeyFile
|-------------------------------------------------------------------------------
|
| PURPOSE: To encrypt a plaintext file using a specified key file.
|
| DESCRIPTION: This routine makes an OT7-format file from a plaintext file,
| encrypting it with a given key file and the current application parameters.
|
| On completion of this call the global Result code will indicate the success 
| or failure of the attempt.
|        
| The plaintext file is treated as binary data for purposes of encryption, so
| any type of file can be encrypted.
|
| The encrypted OT7-format file can be generated in binary or base64 format.
| The specification for base64 encoding is RFC 4648.
|
| HISTORY: 
|    09Mar14 From EncryptFileOT7().
------------------------------------------------------------------------------*/
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code. Also sets the global Result to the same value.
u32 //
EncryptFileUsingKeyFile( OT7Context* e )
{
    u32 f;
    
    // Set the global result to OK, updating later if an error is encountered.
    Result = RESULT_OK;

    // Open the one-time pad key file.
    e->KeyFileHandle = OpenKeyFile( e->KeyFileName );

    // If unable to open the one-time pad key file, then fail to encrypt.
    if( e->KeyFileHandle == 0 )
    {
        // OpenKeyFile() has already printed an error message and set the
        // global result code. 
        
        // Exit via the error path.
        goto ErrorExit;
    }

    // Compute a hash string to identify the key file based on the content of 
    // the first 32 bytes in the file.
    //
    // OUT: RESULT_OK if successful, or some other status code if there was an 
    //      error.
    Result =
        ComputeKeyHash( 
            e->KeyFileName,
                // File name of the one-time pad key file, a zero-terminated
                // ASCII string.
                //
            e->KeyFileHandle,
                // File handle of a one-time pad key file, opened for read-only 
                // or read/write access.
                //
            (u8*) &e->KeyHashBuffer[0],
                // OUT: Output buffer for the key file hash in binary form. The 
                //      size of the buffer is KEY_FILE_HASH_SIZE = 8 bytes.
                //
            (s8*) &e->KeyHashStringBuffer[0] );
                // OUT: Output buffer used to hold the hash string. Must be at  
                //      least (KEY_FILE_HASH_SIZE*2) + 1 bytes.

    // If there was an error computing the file ID hash of the key file, then 
    // try the next key file if any.
    if( Result != RESULT_OK )
    {
        // The error message has already been printed by ComputeKeyHash().
        
        // Exit via the error path.
        goto ErrorExit;
    }
    
    // Look up the starting address of the key using the 'ot7.log' file.
    //            
    // OUT: Offset of the first unused key byte in the file. 
    //
    //      This operation can't fail because absence of a log file or failure 
    //      to find a log entry for the given key file always results in the 
    //      default starting address being used. 
    //
    //      If there is a subsequent failure to update the starting address to 
    //      the 'ot7.log' file after encryption, then the whole encryption 
    //      process will fail to avoid accidental reuse of key bytes.
    e->StartingAddress = 
        LookupOffsetOfFirstUnusedKeyByte( (s8*) &e->KeyHashStringBuffer[0] );
                                                    // A hash string that 
                                                    // identifies the 
                                                    // one-time pad key file.
    // Get the size of the key file. 
    e->KeyFileSize = GetFileSize64( e->KeyFileHandle );
    
    // If there was an error determining the size of the key file, then print 
    // an error message and go try the next key file.
    if( e->KeyFileSize == MAX_VALUE_64BIT )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't get size of key file '%s'.\n", 
                     e->KeyFileName );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_SEEK_IN_KEY_FILE;
 
        // Exit via the error path.
        goto ErrorExit;
    }
    else // Got the key file size.
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "Key file '%s' is %s bytes long.\n", 
                    e->KeyFileName,
                    ConvertIntegerToString64(e->KeyFileSize) );
        }
    }
        
    // Calculate the number of unused bytes in the key file.
    e->UnusedBytes = e->KeyFileSize - e->StartingAddress;
    
    // Start with no extra key bytes used for randomization of fill byte size or
    // randomization of the KeyID.
    e->ExtraKeyUsed = 0;
        
    //--------------------------------------------------------------------------
    // SEEK TO FIRST UNUSED BYTE
    //--------------------------------------------------------------------------
        
    // Seek to the first unused byte in the key file.
    e->Status = SetFilePosition( e->KeyFileHandle, e->StartingAddress );
    
    // If able to seek to the first unused byte in the key file, report the
    // status.
    if( e->Status == 0 )
    {
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "Set file position to %s in key file '%s'.\n", 
                    ConvertIntegerToString64(e->StartingAddress),
                    e->KeyFileName );
        }
    }
    else // Unable to seek to the first unused byte in the key file, so report
         // error and try the next key file if any.
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( 
                "ERROR: Can't set file position to %s in key file '%s'.\n", 
                ConvertIntegerToString64(e->StartingAddress),
                e->KeyFileName );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_SEEK_IN_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
                
    //--------------------------------------------------------------------------
        
    // If the '-nofilename' option was specified, then don't include the
    // FileName field.
    if( IsNoFileName.IsSpecified && (IsNoFileName.Value == 1) )
    {
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "Excluding file name from OT7 record.\n" ); 
        }

        // Use zero for the length of the FileName field.
        e->FileNameSize = 0;
    }
    else // The name of the plaintext file should be included in the OT7 record.
    {
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "Including file name in OT7 record.\n" ); 
        }

        // Calculate the length of the file name not including a zero 
        // terminator byte.
        e->FileNameSize = CountString( NameOfPlaintextFile.Value );
    }
        
    //--------------------------------------------------------------------------
        
    // Open the plaintext for reading binary data.
    e->PlaintextFile = fopen64( NameOfPlaintextFile.Value, "rb" );  

    // If unable to open the plaintext file, then print an error message and 
    // return.
    if( e->PlaintextFile == 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( 
                "ERROR: Can't open plaintext file '%s' for reading.\n", 
                NameOfPlaintextFile.Value );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_READING;

        // Exit via the error path.
        goto ErrorExit;
    }
        
    //--------------------------------------------------------------------------

    // Open the output file for writing binary or base64 data. The "wb" option 
    // causes the file to be created or truncated to zero length if it already 
    // exists. 
    e->Status = 
        OpenFileX( &e->EncryptedFile,
                   NameOfEncryptedOutputFile.Value, 
                   EncryptedFileFormat.Value, 
                   "wb" );  

     // If unable to open the output file, then exit from this routine.
    if( e->Status == 0 )
    {
        // Error message has already been printed and the global result code has 
        // been set to an error code.

        // Exit via the error path.
        goto ErrorExit;
    }
     
    //--------------------------------------------------------------------------

    // Get the size of the plain text file. This is the number of bytes to be 
    // encrypted.
    e->TextSize = GetFileSize64( e->PlaintextFile );
    
    // If there was an error determining the size of the plaintext file, then 
    // print an error message and exit.
    if( e->TextSize == MAX_VALUE_64BIT )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't get size of plaintext file '%s'.\n", 
                     NameOfPlaintextFile.Value );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_SEEK_IN_PLAINTEXT_FILE;
        
        // Exit via the error path.
        goto ErrorExit;
    }
        
    // If the number of fill bytes is unspecified, then pick a random number.
    if( FillSize.IsSpecified == 0 )
    {
        // Eight bytes are needed for generating the number of fill bytes, so 
        // return with an error if there are not at least that many unused bytes
        // in the key file.
        if( e->UnusedBytes < 8 )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Ran out of key bytes in file '%s'.\n", 
                        e->KeyFileName );
            }

            // Set the result code to be returned when the application exits.
            Result = RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD;

            // Exit via the error path.
            goto ErrorExit;
        }

        // Randomly generate the number of fill bytes based on the size of the
        // plain text. The one-time pad file is used as the source of random 
        // numbers for this step.
        e->FillSize = SelectFillSize( e->KeyFileHandle, e->TextSize );

        // Account for having used 8 key bytes when randomizing the fill size.
        e->ExtraKeyUsed += 8;

        // Reduce the number of unused key bytes by the 8 used in the fill size 
        // generation step.
        e->UnusedBytes -= 8;
    }

    // If an error occurred when generating the fill size, then exit with an 
    // error message.
    if( FillSize.Value == MAX_VALUE_64BIT )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read key file '%s'.\n", e->KeyFileName );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_READ_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "Plaintext file size is %s bytes.\n", 
                ConvertIntegerToString64( e->TextSize ) );
                
        printf( "Using %s fill bytes to mask the size of the plaintext.\n", 
                ConvertIntegerToString64( e->FillSize ) );
    }
        
    //--------------------------------------------------------------------------
        
    // Measure how many bytes are required to represent the TextSize number.
    // This will be from 0 to 8 bytes. 
    e->TextSizeFieldSize = NumberOfSignificantBytes( e->TextSize );
    
    // Measure how many bytes are required to represent the FillSize number.
    // This will be from 0 to 8 bytes. 
    e->FillSizeFieldSize = NumberOfSignificantBytes( e->FillSize );
    
    // Make the value for the SizeBits field by combining TextSizeFieldSize with
    // FillSizeFieldSize.
    e->SizeBits = (e->FillSizeFieldSize << 4) | e->TextSizeFieldSize;
        
    //--------------------------------------------------------------------------
 
    // Calculate the size of the body section of the OT7 record. This is the 
    // binary format size. If base64 encoding is used, then the final size will
    // be larger than this value.
    e->BodySize = EXTRAKEYUSED_FIELD_SIZE +  // 1 byte
                  SIZEBITS_FIELD_SIZE +      // 1 byte
                  e->TextSizeFieldSize +     // 0 to 8 bytes
                  e->FillSizeFieldSize +     // 0 to 8 bytes
                  FILENAMESIZE_FIELD_SIZE +  // 2 bytes
                  e->FileNameSize +          // 0 to MAX_FILE_NAME_SIZE bytes
                  e->TextSize +              // 0 to 2^64 bytes
                  e->FillSize +              // 0 to 2^64 bytes
                  SUMZ_FIELD_SIZE;           // 8 bytes
               
    // Print status message if in verbose mode. 
    if( IsVerbose.Value )
    {
        printf( "BodySize is %s bytes.\n",
                 ConvertIntegerToString64( e->BodySize ) );
    }
                   
    //--------------------------------------------------------------------------
        
    // Calculate the number of key bytes needed to initialize the password hash
    // context.
    
    // Use at least one true random key byte for each byte of the password.
    e->TrueRandomBytesRequiredForHashInitialization = 
        CountString( Password.Value );
        
    // Use a minimum of MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT bytes to cover the
    // case where a short password is used.
    if( e->TrueRandomBytesRequiredForHashInitialization < 
        MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT )
    {
        e->TrueRandomBytesRequiredForHashInitialization = 
            MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT;
    }
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( 
            "Hash initialization uses %d bytes from the key file.\n",
            (e->TrueRandomBytesRequiredForHashInitialization * 2) );
    }
        
    //--------------------------------------------------------------------------
 
    // Calculate the number of key bytes needed for the OT7 record -- one byte
    // for each byte of the body plus all of the bytes needed for initialization 
    // of the password hash context. The password context needs to be 
    // initialized twice: once for the header key and once for encrypting the  
    // body.
    e->KeyBytesNeeded = 
        e->BodySize + (e->TrueRandomBytesRequiredForHashInitialization * 2);

    // If there are not enough unused bytes available for encrypting the 
    // whole message, then return with an error message. 
    if( e->UnusedBytes < e->KeyBytesNeeded )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Not enough unused bytes in key file '%s'.\n", 
                    e->KeyFileName );

            printf( "Have %s unused key bytes but need ",
                    ConvertIntegerToString64( e->UnusedBytes ) );
                    
            printf( "%s.\n",
                    ConvertIntegerToString64( e->KeyBytesNeeded ) );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD;

        // Exit via the error path.
        goto ErrorExit;
    }
        
    //--------------------------------------------------------------------------

    // At this point the requirements for encrypting the plaintext have been 
    // met.

    // Use the current offset from the beginning of the key file as the address
    // of the key for encrypting the OT7 record.
    e->KeyAddress = (u64) ftello64( e->KeyFileHandle ); 
             
    //--------------------------------------------------------------------------
    // INITIALIZE PASSWORD HASH STREAM FOR COMPUTING HEADER KEY
    //--------------------------------------------------------------------------

    // If no password has been specified and verbose mode is enabled, then
    // report that the default password is being used.
    if( IsVerbose.Value && (Password.IsSpecified == 0) )
    {
        printf( "Using default password for encryption.\n" );
    }

    // Initialize a Skein1024 hash for computing the header key.
    //
    // This routine reads true random bytes from the current location in the 
    // given key file and XOR's them with the password to make a hash context 
    // that depends on both data sources.
    //
    // OUT: Result code: RESULT_OK on success, or an error code on failure.
    Result =
        InitializeHashWithTrueRandomBytesAndPassword( 
            e,  // Context of the file being encrypted.
                //
            &e->PasswordContext,
                // Hash context to be initialized.
                //
            HEADERKEY_BIT_COUNT,  
                // Size of the hash to be produced in bits.
                //
            Password.Value );
                // The password string to feed into the hash context after the 
                // true random bytes.

    // If the key file could not be read, then return with an error message.
    if( Result != RESULT_OK )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read key file '%s'.\n", e->KeyFileName );
        }

        // Set the result code to be returned by this routine.
        Result = RESULT_CANT_READ_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
        
    // Build the header of the OT7 record in the Header buffer in the OT7Context
    // record. 
     
    // Compute the 8-byte HeaderKey hash.
    //
    //        ============<--- The hash spans this part of the header.
    //        --------------------------------------     
    //        | HeaderKey | KeyIDHash | KeyAddress |     
    //        ------------+-----------+------------+ 
    //        0           8          16           24                             
    //        |             
    //        TextBuffer
    //
    Skein1024_Final( &e->PasswordContext, (u8*) &e->Header[0] );
        
    // Compute the 16-byte hash that is used to encrypt the KeyID and
    // KeyAddress.
    //                    ==========================<--- This second hash 
    //        --------------------------------------     spans this part
    //        | HeaderKey | KeyIDHash | KeyAddress |     of the header.
    //        ------------+-----------+------------+ 
    //        0           8          16           24                             
    //        |             
    //        TextBuffer
    //
    ComputeKeyIDHash128bit( 
        (u8*) &e->Header[0],
                // The HeaderKey value of an OT7 record header. This is an 
                // 8-byte hash.
                //
        KeyID.Value, 
                // KeyID identifies a key definition by number. This is a 
                // value associated with key file(s) used to encrypt an OT7 
                // record. 
                //
        Password.Value,
                // Password is the current password parameter, either 
                // entered on the command line, from a key definition, or 
                // the default password.
                //
        (u8*) &e->Header[KEYIDHASH_FIELD_OFFSET] );
                // OUT: Output buffer for the 128-bit hash produced by this 
                //      routine.
         
    // Save the KeyAddress into a scratch buffer in LSB-to-MSB order.    
    Put_u64_LSB_to_MSB( e->KeyAddress, &e->FillBuffer[0] );
        
    // XOR the KeyAddress with the hash value in the KeyAddress field.
    XorBytes( (u8*) &e->FillBuffer[0],                   // From 
              (u8*) &e->Header[KEYADDRESS_FIELD_OFFSET], // To  
              KEYADDRESS_FIELD_SIZE );                   // ByteCount

    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "KeyAddress = %s.\n",
                 ConvertIntegerToString64( e->KeyAddress ) );
    }
                
    // Zero the KeyAddress from the scratch buffer after use.
    ZeroBytes( e->FillBuffer, KEYADDRESS_FIELD_SIZE );
                       
    //--------------------------------------------------------------------------
       
    // Write out the header to the encrypted file.
    e->BytesWritten = 
        WriteBytesX( &e->EncryptedFile, e->Header, OT7_HEADER_SIZE );
            
    // If the header wasn't entirely written to the encrypted file, then return
    // with an error message.
    if( e->BytesWritten != OT7_HEADER_SIZE )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't write header of encrypted file '%s'.\n", 
                    NameOfEncryptedOutputFile.Value );
                    
            printf( "Tried to write %ld bytes, but actually wrote %ld.\n",
                    (u32) OT7_HEADER_SIZE, e->BytesWritten );
        }

        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_WRITE_ENCRYPTED_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
        
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "OT7 Record Header = '%s'\n",        
                 ConvertBytesToHexString( e->Header, OT7_HEADER_SIZE ) );
    }
               
    // Zero the header buffer after use.
    ZeroBytes( e->Header, OT7_HEADER_SIZE );
          
    //--------------------------------------------------------------------------
    // BEGIN ONE-TIME PAD ENCRYPTION OF THE BODY SECTION OF THE OT7 RECORD.
    //--------------------------------------------------------------------------
        
    //--------------------------------------------------------------------------
    // INITIALIZE PASSWORD HASH STREAM FOR ENCRYPTING THE BODY
    //--------------------------------------------------------------------------

    // Initialize a Skein1024 hash for generating the password hash stream used 
    // when encrypting the body of an OT7 record.
    //
    // This routine reads true random bytes from the current location in the 
    // given key file and XOR's them with the password to make a hash context 
    // that depends on both data sources.
    //
    // OUT: Result code: RESULT_OK on success, or an error code on failure.
    Result =
        InitializeHashWithTrueRandomBytesAndPassword( 
            e,  // Context of the file being encrypted.
                //
            &e->PasswordContext,
                // Hash context to be initialized.
                //
            KEY_BUFFER_BIT_COUNT,   
                // Size of the hash to be produced in bits. 
                //
            Password.Value );
                // The password string to feed into the hash context after the 
                // true random bytes.

    // If the key file could not be read, then return with an error message.
    if( Result != RESULT_OK )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't read key file '%s'.\n", e->KeyFileName );
        }

        // Set the result code to be returned by this routine.
        Result = RESULT_CANT_READ_KEY_FILE;

        // Exit via the error path.
        goto ErrorExit;
    }
        
    // Initialize the number of bytes available in the PseudoRandomKeyBuffer 
    // to 0.
    e->PseudoRandomKeyBufferByteCount = 0;
      
    // Initialize the SumZ checksum context for producing a 64-bit hash
    // value.
    Skein1024_Init( &e->SumZContext, SUMZ_HASH_BIT_COUNT );
 
    // Track the number of bytes put into the TextBuffer starting with an empty
    // buffer.
    e->BytesInTextBuffer = 0;
    
    // Put the number of extra key bytes used into the TextBuffer, advancing the
    // byte count.
    e->TextBuffer[e->BytesInTextBuffer++] = e->ExtraKeyUsed;
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "ExtraKeyUsed is %u bytes.\n", (u32) e->ExtraKeyUsed );
    }
    
    // Put the SizeBits field value into the TextBuffer, advancing the byte 
    // count.
    e->TextBuffer[e->BytesInTextBuffer++] = e->SizeBits;
         
    //--------------------------------------------------------------------------
        
    // Put the significant bytes of the TextSize field in LSB-to-MSB order,
    // storing from 0 to 8 bytes into the TextBuffer.
    Put_u64_LSB_to_MSB_WithTruncation( 
        e->TextSize, 
        (u8*) &e->TextBuffer[e->BytesInTextBuffer],
        e->TextSizeFieldSize );
    
    // Account for the bytes added for the TextSize field.    
    e->BytesInTextBuffer += e->TextSizeFieldSize;
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "TextSize is %s bytes.\n", 
                 ConvertIntegerToString64( e->TextSize ) );
    }
        
    //--------------------------------------------------------------------------
            
    // Put the significant bytes of the FillSize field in LSB-to-MSB order,
    // storing from 0 to 8 bytes into the TextBuffer.
    Put_u64_LSB_to_MSB_WithTruncation( 
        e->FillSize, 
        (u8*) &e->TextBuffer[e->BytesInTextBuffer],
        e->FillSizeFieldSize );
            
    // Account for the bytes added for the FillSize field.    
    e->BytesInTextBuffer += e->FillSizeFieldSize;
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "FillSize is %s bytes.\n", 
                 ConvertIntegerToString64( e->FillSize ) );
    }
        
    //--------------------------------------------------------------------------
         
    // Put the file name size field next, in LSB-to-MSB order.
    Put_u16_LSB_to_MSB( 
        e->FileNameSize, (u8*) &e->TextBuffer[e->BytesInTextBuffer] );
        
    // Account for the bytes added for the FileNameSize field.    
    e->BytesInTextBuffer += sizeof( e->FileNameSize );
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "FileNameSize is %u bytes.\n", (u32) e->FileNameSize );
    }
     
    //--------------------------------------------------------------------------

    // Include the unencrypted bytes of fields ExtraKeyUsed, SizeBits, TextSize, 
    // FillSize, and FileNameSize in the SumZ checksum.
    Skein1024_Update( &e->SumZContext, 
                      (u8*) &e->TextBuffer[0], 
                      e->BytesInTextBuffer );
 
    // Encrypt the ExtraKeyUsed, SizeBits, TextSize, FillSize, and FileNameSize 
    // fields to the output file.
    Result = 
        EncryptBufferToFile( 
            e,  // Context of a file in the process of being encrypted.
                //                 
            e->TextBuffer,
                 // Address of data to be encrypted.
                 //
            e->BytesInTextBuffer ); 
                 // Number of bytes to encrypt.
                 
    // EncryptBufferToFile() will already have printed any error message. 
    
    // If unable to encrypt the buffer to the output file, then exit. 
    if( Result != RESULT_OK )
    {
        // Exit via the error path.
        goto ErrorExit;
    }
  
    //--------------------------------------------------------------------------
    // WRITE FILE NAME FIELD
    //--------------------------------------------------------------------------
        
    // If the file name field is included, then write it next.
    if( e->FileNameSize )
    {
        // Accumulate the unencrypted file name into the checksum without the
        // zero terminator byte.
        Skein1024_Update( 
            &e->SumZContext, 
            (u8*) NameOfPlaintextFile.Value, 
            (u32) e->FileNameSize );

        // Encrypt the file name field to the output file.
        Result = 
            EncryptBufferToFile( 
                e,  // Context of a file in the process of being encrypted.
                    //
                (u8*) NameOfPlaintextFile.Value,
                    // Address of data to be encrypted.
                    //
                e->FileNameSize );
                    // Number of bytes to encrypt.

        // EncryptBufferToFile() will already have printed any error message. 
        
        // If unable to encrypt the buffer to the output file, then exit. 
        if( Result != RESULT_OK )
        {
            // Exit via the error path.
            goto ErrorExit;
        }
    }
      
    //--------------------------------------------------------------------------
    // WRITE TEXTFILL FIELD INTERLEAVING TEXT AND FILL BYTES.
    //--------------------------------------------------------------------------

    // Start with all of the text bytes to be written in the TextFill field.
    e->TextBytesToWriteInField = e->TextSize;
    
    // Start with all of the fill bytes to be written in the TextFill field.
    e->FillBytesToWriteInField = e->FillSize;
    
    // Start with all of the TextFill field to be written.
    e->BytesToWriteInField = e->TextSize + e->FillSize;

    // Start the interleave flag at 1 meaning that a plaintext byte should be
    // written next. This flag alternates between zero and one to control 
    // whether a text byte or fill byte should be written next.
    e->IsTextByteNext = 1;

    // Encrypt the TextFill field as long as bytes remain to be encrypted.
    while( e->BytesToWriteInField )
    {
        // If text bytes remain to be written into the TextFill field, then
        // fetch some from the plaintext file.
        if( e->TextBytesToWriteInField )
        {
            // Calculate the number of plaintext bytes to write on this pass,
            // defaulting to the text buffer size.
            e->TextBytesToWriteThisPass = TEXT_BUFFER_SIZE;

            // If there is less than a full block of plaintext left to write, 
            // then just write what is available.
            if( e->TextBytesToWriteThisPass > e->TextBytesToWriteInField )
            {
                e->TextBytesToWriteThisPass = e->TextBytesToWriteInField;
            }

            // Read a block of text bytes to the TextBuffer.
            e->BytesRead = ReadBytes( e->PlaintextFile, 
                                      (u8*) &e->TextBuffer[0],
                                      e->TextBytesToWriteThisPass );

            // If the plaintext block could not be read, then return with an 
            // error message.
            if( e->BytesRead != e->TextBytesToWriteThisPass )
            {
                // Print error message if verbose output is enabled.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Can't read plaintext file '%s'.\n", 
                            NameOfPlaintextFile.Value );
                }
            
                // Set the result code to be returned when the application 
                // exits.
                Result = RESULT_CANT_READ_PLAINTEXT_FILE;
        
                // Exit via the error path.
                goto ErrorExit;
            }
                
            // Include the text bytes in the SumZ checksum hash.
            Skein1024_Update( 
                &e->SumZContext, 
                &e->TextBuffer[0], 
                e->TextBytesToWriteThisPass );
        } 
        else // No text bytes remain to be written, but fill bytes may be.
        {
            // Write no text bytes this pass because there are none left.
            e->TextBytesToWriteThisPass = 0;
                
            // Switch the interleave flag to 0 meaning that a fill byte 
            // should be written next. 
            e->IsTextByteNext = 0;
        } 
        
        // If fill bytes remain to be written into the TextFill field, then
        // calculate how many to write on this pass.
        if( e->FillBytesToWriteInField )
        {
            // Calculate the number of fill bytes to write on this pass, 
            // defaulting to the fill buffer size.
            e->FillBytesToWriteThisPass = FILL_BUFFER_SIZE;

            // If there is less than a full block of fill bytes left to write, 
            // then just write what is available.
            if( e->FillBytesToWriteThisPass > e->FillBytesToWriteInField )
            {
                e->FillBytesToWriteThisPass = e->FillBytesToWriteInField;
            }
            
            // Generate a block of pseudo-random fill bytes from the password 
            // hash stream.
            for( f = 0; f < e->FillBytesToWriteThisPass; f++ )
            {
                e->FillBuffer[f] = GetNextByteFromPasswordHashStream(e);
            }
            
            // Zero f so it will be clear on exit from this routine.
            f = 0;
             
            // Don't include fill bytes in the SumZ checksum because a fill byte 
            // error doesn't corrupt the plaintext.
        }
        else // No fill bytes remain to be written, but text bytes may be.
        {
            // Write no fill bytes this pass because there are none left.
            e->FillBytesToWriteThisPass = 0;
            
            // Switch the interleave flag to 1 meaning that a text byte should 
            // be written next. 
            e->IsTextByteNext = 1;
        } 
        
        // Calculate the total number of bytes to write to the TextFill field on
        // this pass. This can be up to twice the BLOCK_SIZE.
        e->BytesToWriteThisPass = 
            e->TextBytesToWriteThisPass + e->FillBytesToWriteThisPass;
            
        // Interleave text and fill bytes to the TextFillBuffer.
        InterleaveTextFillBytes( e );
         
        //----------------------------------------------------------------------
        // ENCRYPT A BLOCK OF TEXT AND/OR FILL BYTES.
        //----------------------------------------------------------------------

        // Encrypt the block of text/fill data to the output file.
        Result = 
            EncryptBufferToFile( 
                e,  // Context of a file in the process of being encrypted.
                    //
                e->TextFillBuffer,
                    // Address of data to be encrypted.
                    //
                e->BytesToWriteThisPass );
                    // Number of bytes to encrypt.

        // EncryptBufferToFile() will already have printed any error message. 
            
        // If unable to encrypt the buffer to the output file, then exit. 
        if( Result != RESULT_OK )
        {
            // Exit via the error path.
            goto ErrorExit;
        }
  
        // Reduce the text and fill left to be encrypted by the amount done 
        // this pass.
        e->BytesToWriteInField -= e->BytesToWriteThisPass;
        
        // Reduce the text left to be encrypted by the amount done this 
        // pass.
        e->TextBytesToWriteInField -= e->TextBytesToWriteThisPass;
    
        // Reduce the fill left to be encrypted by the amount done this 
        // pass.
        e->FillBytesToWriteInField -= e->FillBytesToWriteThisPass;
    }
    
    //--------------------------------------------------------------------------
    
    // Close the plain text file since all data from the file has been written
    // into the TextFill field.
    e->Status = fclose( e->PlaintextFile );
    
    // Mark the plain text file as closed.
    e->PlaintextFile = 0;
    
    // If there was an error closing the plaintext file, then report the error.
    if( e->Status )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Got error code %d when closing file '%s'.\n", 
                     e->Status,
                     NameOfPlaintextFile.Value );
        }
     
        // Set the result code to be returned by the application.
        Result = RESULT_CANT_CLOSE_PLAINTEXT_FILE;
        
        // Exit via the error path.
        goto ErrorExit;
    }
    
    //--------------------------------------------------------------------------
    // WRITE CHECKSUM FIELD
    //--------------------------------------------------------------------------
        
    // Output the checksum hash to the TextFillBuffer.
    Skein1024_Final( &e->SumZContext, (u8*) &e->TextFillBuffer[0] );

    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "Embedded checksum is '%s'.\n",
                 ConvertBytesToHexString( (u8*) &e->TextFillBuffer[0], 
                                          SUMZ_HASH_BYTE_COUNT ) );
    }                
      
    // Encrypt the checksum field to the output file.
    Result = 
        EncryptBufferToFile( 
            e,  // Context of a file in the process of being encrypted.
                //
            e->TextFillBuffer,
                // Address of data to be encrypted.
                //
            SUMZ_HASH_BYTE_COUNT );// Number of bytes to encrypt.

    // EncryptBufferToFile() will already have printed any error message. 
        
    // If unable to encrypt the buffer to the output file, then exit. 
    if( Result != RESULT_OK )
    {
        // Exit via the error path.
        goto ErrorExit;
    }

    // Close the encrypted output file, completing any necessary encoding and 
    // write that data to disk. Returns 0 on success, or an error code 
    // otherwise. This handles writing any padding characters ('=') for base64.
    e->Status = CloseFileAfterWritingX( &e->EncryptedFile );

    // If unable to close the encrypted file properly, then return with an 
    // error message.
    if( e->Status )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't close encrypted file '%s'.\n", 
                    NameOfEncryptedOutputFile.Value );
        }
            
        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_CLOSE_ENCRYPTED_FILE;
    
        // Zero the encrypted file handle to keep from attempting to close 
        // again on exit.
        ZeroBytes( (u8*) &e->EncryptedFile, sizeof( FILEX ) );

        // Exit via the error path.
        goto ErrorExit;
    }

    //--------------------------------------------------------------------------
    // ENCRYPTED OUTPUT FILE IS COMPLETE.
    //--------------------------------------------------------------------------

    // Get the address of the next unused key byte in the one-time pad file by
    // reading the current file position.
    e->EndingAddress = (u64) ftello64( e->KeyFileHandle );
    
    // Update the 'ot7.log' file to include the new offset for the first unused 
    // byte in the file. Returns RESULT_OK if successful, otherwise an error 
    // code.
    Result = 
        SetOffsetOfFirstUnusedKeyByte( 
            (s8*) &e->KeyHashStringBuffer[0],
                // A hash string that identifies the key file.
                //
            e->EndingAddress );
                // New first unused byte in the file identified by the hash 
                // string.
 
    // SetOffsetOfFirstUnusedKeyByte() will already have printed any error 
    // message at this point.
         
    // If there was an error updating the log file, then return with an error
    // message.
    if( Result != RESULT_OK )
    {
        // Exit via the error path.
        goto ErrorExit;
    }
 
    // Calculate the total number of bytes used to encrypt the message from the
    // StartingAddress to the EndingAddress.
    e->TotalUsedBytes = e->EndingAddress - e->StartingAddress;
        
    //--------------------------------------------------------------------------
  
    // If the used key bytes in the one-time pad file should be erased, then do 
    // that here.
    if( IsEraseUsedKeyBytes.Value )
    {
        // Erasing the true random key bytes after use provides forward 
        // security. Using this option means that the OT7 record just produced 
        // can't be decrypted using the same key file used for encrypting it. 
        // Some other copy of the key file will need to be used for decryption.
        
        // Erase the used key bytes from the one-time pad file.
        e->NumberErased =
            EraseUsedKeyBytesInOneTimePad( 
                e,  // Context of a file after it has been encrypted or 
                    // decrypted, with the key file open for write access.
                    //
                e->StartingAddress,
                    // Starting address of the used key bytes to be erased. 
                    // This is a byte offset from the beginning of the file. 
                    //
                e->TotalUsedBytes );
                    // Size of the used key to be erased in bytes.

         // If all of the used bytes have been erased, then report that in
         // verbose mode.
        if( e->NumberErased == e->TotalUsedBytes )
        {
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Key bytes have been erased after use.\n" );
            }
        }
        else // Some of the used bytes are not erased, so exit with an error
             // message.
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( 
                    "ERROR: Can't erase key bytes in one-time pad file '%s'.\n", 
                    e->KeyFileName );
            }
            
            // Set the error code to be returned so that caller will know that
            // key bytes were not erased.
            Result = RESULT_CANT_ERASE_USED_KEY_BYTES;
    
            // Exit via the error path.
            goto ErrorExit;
        }
    }

    //--------------------------------------------------------------------------
   
    // Close the key file.
    e->Status = fclose( e->KeyFileHandle );
    
    // Mark the key file handle as closed to avoid a reclose attempt on exit.
    e->KeyFileHandle = 0;

    // If unable to close the key file properly, then return with an error 
    // message.
    if( e->Status )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't close key file '%s'.\n", e->KeyFileName );
        }
            
        // Set the result code to be returned when the application exits.
        Result = RESULT_CANT_CLOSE_KEY_FILE;
 
        // Exit via the error path.
        goto ErrorExit;
    }

    // Print the final result if verbose output is enabled.
    if( IsVerbose.Value )
    {
        // Calculate the total number of unused key bytes in the key file after
        // encrypting the message.
        e->UnusedBytes = e->KeyFileSize - e->EndingAddress;
 
        printf( "DONE: %s unused bytes left in key file '%s'.\n", 
                ConvertIntegerToString64( e->UnusedBytes ),
                e->KeyFileName );
                
        printf( "\nFile '%s' has been encrypted to file '%s'.\n\n", 
                NameOfPlaintextFile.Value,
                NameOfEncryptedOutputFile.Value );
    }
         
    //--------------------------------------------------------------------------
    // SUCCESSFUL COMPLETION OF ENCRYPTION.
    //--------------------------------------------------------------------------
     
    // Go to the common exit path.
    goto Exit;
        
    //==========================================================================
         
////////////
ErrorExit:// All errors come here.
////////////

    // Close any open files.

    // Close the plaintext file if it is open.
    if( e->PlaintextFile )
    {
        fclose( e->PlaintextFile );
    }

    // Close the encrypted output file if is open.
    if( e->EncryptedFile.FileHandle )
    {
        fclose( e->EncryptedFile.FileHandle );
        
        // Mark the file as closed.
        e->EncryptedFile.FileHandle = 0;
    }

    // Close the key file if it is open.
    if( e->KeyFileHandle )
    {
        fclose( e->KeyFileHandle );
    }
    
    // Delete the partial encrypted file if it exists.
    remove( NameOfEncryptedOutputFile.Value );

///////
Exit:// Common exit path for success and failure.
///////

    // Clear all the buffers used by this routine in the OT7Context record.
    ZeroBytes( (u8*) &e->EncryptedFile, sizeof( FILEX ) );
    ZeroBytes( (u8*) e->FillBuffer, FILL_BUFFER_SIZE );
    ZeroBytes( (u8*) e->Header, OT7_HEADER_SIZE );
    ZeroBytes( (u8*) e->KeyIDHash128bit, KEYIDHASH128BIT_BYTE_COUNT );
    ZeroBytes( (u8*) &e->PasswordContext, sizeof( Skein1024Context ) );
    ZeroBytes( (u8*) &e->SumZContext, sizeof( Skein1024Context ) );
    ZeroBytes( (u8*) e->TextBuffer, TEXT_BUFFER_SIZE );
    ZeroBytes( (u8*) e->TextFillBuffer, TEXTFILL_BUFFER_SIZE );
    
    // Clear all the working variables used by this routine in the OT7Context
    // record.
    e->BodySize = 0;
    e->BytesInTextBuffer = 0;
    e->BytesRead = 0;
    e->BytesWritten = 0;
    e->BytesToWriteInField = 0;
    e->BytesToWriteThisPass = 0;
    e->EndingAddress = 0;
    e->ExtraKeyUsed = 0;
    e->FileNameSize = 0;
    e->FillBytesToWriteInField = 0;
    e->FillBytesToWriteThisPass = 0;
    e->FillSize = 0;
    e->FillSizeFieldSize = 0;
    e->IsTextByteNext = 0;
    e->KeyAddress = 0;
    e->KeyBytesNeeded = 0;
    e->KeyFileHandle = 0;
    e->KeyFileSize = 0;
    e->NumberErased = 0;
    e->PlaintextFile = 0;
    e->PseudoRandomKeyBufferByteCount = 0;
    e->SizeBits = 0;
    e->StartingAddress = 0;
    e->Status = 0;
    e->TextBytesToWriteInField = 0;
    e->TextBytesToWriteThisPass = 0;
    e->TextSize = 0;
    e->TextSizeFieldSize = 0;
    e->TotalUsedBytes = 0;
    e->TrueRandomBytesRequiredForHashInitialization = 0;
    e->UnusedBytes = 0;
    
    //--------------------------------------------------------------------------
    // Return the result code RESULT_OK if the encryption process was 
    // successful. Any other code indicates that an error occurred which may or 
    // may not be recoverable using a different key file.  
    return( Result );
}

/*------------------------------------------------------------------------------
| EraseUsedKeyBytesInOneTimePad
|-------------------------------------------------------------------------------
|
| PURPOSE: To erase key bytes in a one-time pad file after using them.
|
| DESCRIPTION: Erasing the key used to encrypt/decrypt a message provides 
| forward security.  
|
| Erasure consists of overwriting key bytes with pseudo-random values from the
| password hash stream. 
|
| Note that on some file systems such as the log-structured kind, overwriting 
| data doesn't erase the prior value from the media.
|
| This routine uses TrueRandomKeyBuffer as a working buffer. This routine 
| changes the location of the key file pointer.
|
| Returns the number of bytes erased.
|
| HISTORY:  
|    20Oct13 Revised comments.
|    20Jan14 Changed to use 64-bit parameters for large file support.
|    26Jan14 Added file name for error messages.
|    16Mar14 Revised to use OT7Context record and changed values written into
|            key file to be from the pseudo-random password hash stream instead
|            of 0xFF. This makes automated detection of key erasure more 
|            difficult. Added clearing of the TrueRandomKeyBuffer on exit.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes erased.
u64 //
EraseUsedKeyBytesInOneTimePad( 
    OT7Context* c,
            // Context of a file after it has been encrypted or decrypted, with
            // the key file open for write access.
            //
    u64 StartingAddress,
            // Starting address of the used key bytes to be erased. This is a 
            // byte offset from the beginning of the file. 
            //
    u64 UsedBytesToErase )
            // Size of the used key to be erased in bytes.
{
    s32 SeekResult;
    u32 i;
    u64 NumberErased;
    u64 BytesWritten;
    u64 BytesToWriteThisPass;
        
    // Start with no bytes erased.
    NumberErased = 0;

    // Seek to the first key byte in the one-time pad file. Returns 0 on 
    // success, or -1 if there was an error.
    SeekResult = SetFilePosition( c->KeyFileHandle, StartingAddress );

    // If there was a seek error, then return with an error message.
    if( SeekResult != 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't set file position in one-time pad file '%s'.\n", 
                    c->KeyFileName );
        }

        // Exit, returning zero to mean an error occurred.
        goto Exit;
    }
 
    // While there are used bytes remaining to be erased.
    while( UsedBytesToErase )
    {
        // Calculate the number of bytes to write on this pass, defaulting 
        // to the key buffer size.
        BytesToWriteThisPass = KEY_BUFFER_SIZE;

        // If there is less than a full buffer left to write, then just write
        // what is available.
        if( BytesToWriteThisPass > UsedBytesToErase )
        {
            BytesToWriteThisPass = UsedBytesToErase;
        }
        
        // Put a block of pseudo-random values into the TrueRandomKeyBuffer.
        for( i = 0; i < BytesToWriteThisPass; i++ )
        {
            c->TrueRandomKeyBuffer[i] = 
                GetNextByteFromPasswordHashStream(c);
        }
   
        // Write the block of pseudo-random bytes to the one-time pad file.
        BytesWritten = 
            WriteBytes( c->KeyFileHandle, 
                        c->TrueRandomKeyBuffer, 
                        BytesToWriteThisPass );
        
        // Increment the number erased by the amount erased this pass.
        NumberErased += BytesWritten;

        // If the block wasn't entirely written to the one-time pad file,
        // then return with an error message.
        if( BytesWritten != BytesToWriteThisPass )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't write to one-time pad file '%s'.\n", 
                        c->KeyFileName );
            }

            // Exit, returning the number of bytes erased.  
            goto Exit;
        }

        // Reduce the byte left to be erased by the amount done this pass.
        UsedBytesToErase -= BytesWritten;
    }

///////
Exit://
///////

    // Zero the TrueRandomKeyBuffer used by this routine.
    ZeroBytes( c->TrueRandomKeyBuffer, KEY_BUFFER_SIZE );

    // Return the number of bytes erased.
    return( NumberErased );
}

/*------------------------------------------------------------------------------
| FindNonWhitespaceByteInSegment
|-------------------------------------------------------------------------------
|
| PURPOSE: To find a non-whitespace byte in a memory segment.
|
| DESCRIPTION: Returns address of the byte or 0 if not found.
|
| HISTORY: 
|    16Nov13 From FindByteInBytes().
------------------------------------------------------------------------------*/
    // OUT: Address of a byte found in the segment, or 0 if none found.
u8* //
FindNonWhitespaceByteInSegment( u8* Start, u8* End )
{
    // Scan the bytes in the segment.
    while( Start < End )
    {
        // If a non-whitespace byte was found, then return the address of the
        // byte.
        if( IsWhiteSpace(*Start) == 0 ) 
        {
            return( Start );
        }
    
        // Advance to the next byte.
        Start++;
    }
    
    // Return 0 if no matching byte was found.
    return( 0 );
}

/*------------------------------------------------------------------------------
| FindPasswordInKeyDefinition
|-------------------------------------------------------------------------------
|
| PURPOSE: To get the password assigned to a key definition if there is one.
|
| DESCRIPTION: If the key definition contains a password, a copy is made to 
| a dynamically allocated buffer and then returned to the caller.
|
| A password in a key definition is defined using the '-p' tag, like this:
|
|                         -p "this is a password"
| HISTORY: 
|    19Feb14 From AugmentCommandLineParametersFromKeyDefinition().
|    22Feb14 Factored out ParseWordOrQuotedPhrase().
------------------------------------------------------------------------------*/
    // OUT: Password string address, or zero if none is found. The string is a
    //      dynamically allocated copy of the password in the key definition.
s8* //
FindPasswordInKeyDefinition( 
    List* KeyMapList,
            // The contents of a "key.map" file, a list of strings where each
            // string is a line of text. Leading and trailing whitespace has
            // been removed from each line. Comments have been stripped out.
            //
    Item* TheKeyDefinition )
            // The place in the KeyMapList where a key definition begins,
            // a line of test beginning with the phrase "KeyID".
{
    s8* S;
    s8* ResultString;
    u32 v;
    ThatItem C;
    static s8 ParameterValueString[MAX_PARAMETER_VALUE_SIZE];
    
    // Set the default result string address to zero to signal a missing 
    // password.
    ResultString = 0;
      
    // Set up a list cursor to refer to the given key definition in the key map 
    // list.
    C.TheList = KeyMapList;
    C.TheItem = TheKeyDefinition;
    
    // Here's the current situation:
    //
    //   C.TheItem->DataAddress ===> "KeyID( 123 )"
    //                                {
    //                                   ...the parameters of the key...
    //                                }
    
    // Advance past the "KeyID" string to the next line.
    ToNextItem(&C);

    // Process each line of the key definition, stopping when the end of the
    // definition is reached. Allow for the possibility that the user forgot 
    // to mark the end of the definition with a "}" by treating the end of 
    // the list, or the beginning of a new definition as the end of the 
    // definition.
    while( C.TheItem && 
           ( IsPrefixForString( "}", (s8*) C.TheItem->DataAddress ) == 0) &&
           ( IsPrefixForString( "KeyID", (s8*) C.TheItem->DataAddress ) == 0) )
    {
        // If the current string contains a password parameter tag '-p', then
        // parse the password to the local buffer.
        if( IsPrefixForString( "-p", (s8*) C.TheItem->DataAddress ) )
        {
            // Use S to refer to the beginning of the parameter string.
            //
            // This is the situation:
            //
            //     S
            //     |
            //     v
            //     -p 'this is a password'
            // or  -p "this is a password"
            // or  -p An0therPassword
            //
            S = (s8*) C.TheItem->DataAddress;
            
            // Advance S to the character after '-p'.
            S += 2;
            
            //       S
            //       |
            //       v
            //     -p 'this is a password'
            // or  -p "this is a password"
            // or  -p An0therPassword
        
            // Parse the next word or quoted phrase from a string, removing any 
            // quotes. Use 'v' to count the number of bytes in the value string
            // parsed from the text line. 
            v = ParseWordOrQuotedPhrase( 
                    &S,   // IN/OUT: Address of the address of the current 
                          //         character in the string being parsed.
                          //
                    (s8*) &ParameterValueString[0],
                          // Address of the output buffer where the word or 
                          // phrase should be placed.
                          //
                    MAX_PARAMETER_VALUE_SIZE );
                          // Size of the output buffer in bytes.
              
            // If a password string was parsed to the local buffer, then make a
            // duplicate for returning to the caller.
            if( v > 0 )
            {
                ResultString = 
                    DuplicateString( (s8*) &ParameterValueString[0] );
            }
             
            // Go clean up and return the result.
            goto CleanUp;
        }        

        // Advance to the next line of the key definition.
        ToNextItem(&C);
    }
    
    // At this point the end of the key definition was reached without finding
    // a password.
 
//////////    
CleanUp://
//////////  
  
    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential
    // for information leakage.
    //--------------------------------------------------------------------------
    
    // Zero the local variables except for ResultString.
    S = 0;
    v = 0;
      
    // Zero the Item cursor record.
    ZeroBytes( (u8*) &C, sizeof(ThatItem) );
      
    // Zero the ParameterValueString buffer.
    ZeroBytes( (u8*) &ParameterValueString[0], MAX_PARAMETER_VALUE_SIZE );
     
    // Zero all of the stack locations used to pass parameters into this
    // routine.
    KeyMapList = 0;
    TheKeyDefinition = 0;
    
    // Return the result password string or zero if none found. 
    return( ResultString );
}

/*------------------------------------------------------------------------------
| FindStringInString
|-------------------------------------------------------------------------------
|
| PURPOSE: To find the address of a substring in another string.
|
| DESCRIPTION: Matching is case-sensitive. Returns 0 if not found.
|
| This can be further optimized.
|
| ASSUMES: Strings are terminated with a 0.
|
| HISTORY: 
|    04Apr91
|    02Jan97 simplified logic.
|    30Jul01 Optimized for speed.
|    27Nov13 Made case-sensitive rather than insensitive.
------------------------------------------------------------------------------*/
    // OUT: Address of substring in the string, or 0 if not found.
s8* //
FindStringInString( s8* SubString, s8* String )
{
    s8 FirstSub;
    
    // Get the first character of the substring.
    FirstSub = *SubString;
    
    // Until the end of the main string has been reached.
    while( *String )
    {
        // If the current character in String is the same as the first 
        // character of the SubString.
        if( *String == FirstSub )
        {
            // If the substring matches the string over the entire length of 
            // the substring.
            if( IsPrefixForString( SubString, String ) )
            {
                // Return the location of the match.
                return( String );
            }
        }
        
        // Advance to the next character of the main string.
        String++;
    }
    
    // Unable to find the substring in the string, so return 0.
    return(0);
}

/*------------------------------------------------------------------------------
| Get_u16_LSB_to_MSB
|-------------------------------------------------------------------------------
|
| PURPOSE: To fetch a 16-bit integer from a buffer where it is stored in
|          LSB-to-MSB order.
|
| DESCRIPTION: This makes integers for the kind of CPU that is running this 
| code, unpacking it from a standard byte order used for data interchange. 
|
| HISTORY: 
|    26Dec13 From Get_u32_LSB_to_MSB().
------------------------------------------------------------------------------*/
    // OUT: The 16-bit integer unpacked from the buffer.
u16 //
Get_u16_LSB_to_MSB( u8* Buffer )
{
    u16 n;
    
    // Assemble the 16-bit result from the first two bytes in the buffer.
    n =    (u16) Buffer[0];
    n |=  ((u16) Buffer[1]) << 8;
    
    // Return the integer.
    return( n );
}

/*------------------------------------------------------------------------------
| Get_u32_LSB_to_MSB
|-------------------------------------------------------------------------------
|
| PURPOSE: To fetch a 32-bit integer from a buffer where it is stored in
|          LSB-to-MSB order.
|
| DESCRIPTION: This makes integers for the kind of CPU that is running this 
| code, unpacking it from a standard byte order used for data interchange. 
|
| HISTORY: 
|    03Nov13 From WriteU32().
|    09Nov13 Made more efficient.
------------------------------------------------------------------------------*/
    // OUT: The 32-bit integer unpacked from the buffer.
u32 //
Get_u32_LSB_to_MSB( u8* Buffer )
{
    u32 n;
    
    // Assemble the 32-bit result from the first four bytes in the buffer.
    n =  (u32) Buffer[3]; n <<= 8;
    n |= (u32) Buffer[2]; n <<= 8;
    n |= (u32) Buffer[1]; n <<= 8;
    n |= (u32) Buffer[0];
    
    // Return the integer.
    return( n );
}

/*------------------------------------------------------------------------------
| Get_u64_LSB_to_MSB
|-------------------------------------------------------------------------------
|
| PURPOSE: To fetch a 64-bit integer from a buffer where it is stored in
|          LSB-to-MSB order.
|
| DESCRIPTION: This makes integers for the kind of CPU that is running this 
| code, unpacking it from a standard byte order used for data interchange. 
|
| HISTORY: 
|    09Nov13 From Get_u32_LSB_to_MSB().
------------------------------------------------------------------------------*/
    // OUT: The 64-bit integer unpacked from the buffer.
u64 //
Get_u64_LSB_to_MSB( u8* Buffer )
{
    u64 n;
    
    // Assemble the 64-bit result from the first 8 bytes in the buffer which
    // are stored in LSB-to-MSB order.
    n =  (u64) Buffer[7]; n <<= 8;
    n |= (u64) Buffer[6]; n <<= 8;
    n |= (u64) Buffer[5]; n <<= 8;
    n |= (u64) Buffer[4]; n <<= 8;
    n |= (u64) Buffer[3]; n <<= 8;
    n |= (u64) Buffer[2]; n <<= 8;
    n |= (u64) Buffer[1]; n <<= 8;
    n |= (u64) Buffer[0];  
    
    // Return the integer.
    return( n );
}

/*------------------------------------------------------------------------------
| Get_u64_LSB_to_MSB_WithTruncation
|-------------------------------------------------------------------------------
|
| PURPOSE: To fetch a 64-bit integer from a buffer where it is stored in
|          LSB-to-MSB order, skipping any bytes at the end known to be zero.
|
| DESCRIPTION: This makes integers for the kind of CPU that is running this 
| code, unpacking it from a standard byte order used for data interchange. 
| It also may skip reading bytes known to be zero at the MSB end.
|
| The ByteCount parameter limits the number of bytes read from the buffer to be
| no more than ByteCount.  
|
| This is the companion routine to Put_u64_LSB_to_MSB_WithTruncation().
|
| HISTORY: 
|    08Feb14 From Put_u64_LSB_to_MSB_WithTruncation().
------------------------------------------------------------------------------*/
    // OUT: The 64-bit integer unpacked from the buffer.
u64 //
Get_u64_LSB_to_MSB_WithTruncation( u8* Buffer, u8 ByteCount )
{
    u64 n;
    u64 b;
    u8  ShiftCount;
    
    // Limit ByteCount to the size of the integer.
    if( ByteCount > sizeof(u64) )
    {
        ByteCount = sizeof(u64);
    }
    
    // Start the integer accumulator at zero.
    n = 0;
    
    // Initialize the ShiftCount for field alignment to be 0.
    ShiftCount = 0;
    
    // Get the bytes of n in LSB-to-MSB order from the buffer, skipping any
    // truncated bytes known to be zero.
    while( ByteCount-- )
    {
        // Copy the current least-significant byte of the integer from the
        // buffer, advancing the buffer pointer by one byte.
        b = (u64) *Buffer++;
        
        // Left shift the byte to align it to its location in the integer.
        b <<= ShiftCount;
        
        // Merge the aligned byte with the integer accumulator value.
        n |= b;
        
        // Add 8 to the shift count in preparation for the next byte.
        ShiftCount += 8;
    }
    
    // Return the integer.
    return( n );
}
  
/*------------------------------------------------------------------------------
| GetFileSize64
|-------------------------------------------------------------------------------
|
| PURPOSE: To return the size of a given file in bytes.
|
| DESCRIPTION: Returns the number of data bytes in the file. Supports large
| files requiring 64-bit integers to represent the size.
|
| HISTORY: 
|    06Oct13 Revised comments.
|    09Nov13 Change to support larger files needing 64-bit integers.
|    29Dec13 Added error handling.
------------------------------------------------------------------------------*/
    // OUT: The number of bytes in the file, or MAX_VALUE_64BIT if there was
    //      an error.
u64 //
GetFileSize64( FILE* F )
{
    s32 Status;
    u64 EndPosition;
    u64 CurrentPosition;

    // Preserve the current file position.
    CurrentPosition = (u64) ftello64( F );

    // Set the file position to the end of the file.
    // Returns 0 on success, or -1 if an error.
    Status = (s32) fseeko64( F, (s64) 0, SEEK_END );

    // If there was a seek error, then return MAX_VALUE_64BIT as an error code.
    if( Status )
    {
        return( MAX_VALUE_64BIT );
    }
    
    // Get the position of the file pointer at the end of the file which is also 
    // the number of data bytes in the file.
    EndPosition = (u64) ftello64( F );

    // Restore original file position, set relative to the beginning of the 
    // file. Returns 0 on success, or -1 if an error.
    Status = (s32) fseeko64( F, (s64) CurrentPosition, SEEK_SET ); 
    
    // If there was a seek error, then return MAX_VALUE_64BIT as an error code.
    if( Status )
    {
        return( MAX_VALUE_64BIT );
    }
    
    // Return the number of bytes in the file.
    return( EndPosition );
}

/*------------------------------------------------------------------------------
| GetNextByteFromPasswordHashStream
|-------------------------------------------------------------------------------
|
| PURPOSE: To get the next byte in the stream of pseudo-random values tied to
|          the password and key file.
|
| DESCRIPTION: Initialize the PasswordContext and zero 
| PseudoRandomKeyBufferByteCount before generating values with this routine.
|
| Bytes from this stream are used for encryption and also for generating filler
| bytes.
|
| HISTORY: 
|    28Feb14 
|    15Mar14 Revised to use buffer in OT7Record instead of global buffer.
------------------------------------------------------------------------------*/
    // OUT: The next byte in the password hash stream, a pseudo-random key.
u8  // 
GetNextByteFromPasswordHashStream( OT7Context* c )
{
    u8 AByte;
    
    // If there are no bytes in the pseudo-random key buffer, then generate a  
    // block from the password hash context.
    if( c->PseudoRandomKeyBufferByteCount == 0 )
    {
        // Generate the password hash bytes to the PseudoRandomKeyBuffer.
        Skein1024_Final( &c->PasswordContext, c->PseudoRandomKeyBuffer );

        // Reset the content counter for the PseudoRandomKeyBuffer to indicate
        // that the buffer is full of key data.
        c->PseudoRandomKeyBufferByteCount = KEY_BUFFER_SIZE;
    }
    
    // Fetch the next byte from the pseudo-random key buffer.
    AByte = c->PseudoRandomKeyBuffer[KEY_BUFFER_SIZE - 
                                     c->PseudoRandomKeyBufferByteCount]; 
                                  
    // Erase the byte from the buffer.
    c->PseudoRandomKeyBuffer[KEY_BUFFER_SIZE - 
                             c->PseudoRandomKeyBufferByteCount] = 0;
                               
    // Account for having used one of the pseudo-random key bytes.
    c->PseudoRandomKeyBufferByteCount--;
    
    // Return the byte.
    return( AByte );
}

/*------------------------------------------------------------------------------
| IdentifyDecryptionKey
|-------------------------------------------------------------------------------
|
| PURPOSE: To identify a decryption key based on command line parameters and
|          the header of the file being decrypted.
|
| DESCRIPTION: This routine fills in missing information not given on the 
| command line by using data found in a 'key.map' file or by using default 
| settings.
|
| This routine locates the decryption key information based on fully or 
| partially qualified references to the key entered on the command line, or 
| derived from the header of the file being decrypted.
|
| Several options exist depending on what input was given on the command line. 
| The key file may be specified by name, or a reference to a key definition in 
| a 'key.map' file may be given via some sort of identifier (-KeyID or -ID 
| options).
|
| If no key file or definition is supplied on the command line, then a search
| is made throuth the 'key.map' file for a definition that matches the HeaderKey
| of the file being decrypted.
|
| Once a key definition is found, then all of the key files of that definition
| become candidates for decrypting the file, each being tried until there is
| a successful decryption. All other parameters in the key definition are also
| applied to supplement parameters not already specified on the command line.
|
| HISTORY: 
|    20Mar14 From IdentifyEncryptionKey().
------------------------------------------------------------------------------*/
void
IdentifyDecryptionKey( OT7Context* d )
{
    // Initialize the d->KeyAddress field to zero to mark it as unknown.
    d->KeyAddress = 0;
    
    // If a 'key.map' file exists and has not yet been read into memory, then 
    // read it into a linked list of text strings.
    if( KeyMapList.IsSpecified == 0 )
    {
        // Read the key map file as a list of strings, appending them to the
        // given list.
        ReadKeyMap( 
            KeyMapFileName.Value, 
                // File name string for the key map file, defaulting to
                // 'key.map'.
                //
            KeyMapList.Value );
                // List to receive the contents of the key map when is read.
                
        // If data was read from the key map file, then set the IsSpecified
        // flag to 1.
        if( KeyMapList.Value->ItemCount )
        {
            KeyMapList.IsSpecified = 1;
                
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Read key map file '%s' into memory.\n", 
                         KeyMapFileName.Value );
            }
        }
    }
    
    //--------------------------------------------------------------------------

    // If a key map has been loaded into memory, then look up additional key 
    // information needed to for decrypting the file.
    if( KeyMapList.IsSpecified )
    {
        // If the KeyID has been specified on the command line, use it to find
        // the key definition.
        if( KeyID.IsSpecified )
        {
            // Find the key definition given the KeyID.
            d->TheKeyDefinition = 
                LookupKeyDefinitionByKeyID( 
                    KeyMapList.Value, 
                    KeyID.Value );
        }
        else // A KeyID has not been specified on the command line, so decode it
             // from the OT7 file header using a trial-and-error search through 
             // the key definitions in the key map list.
        {
            // If a password has been specified on the command line, then use
            // it as the only password when searching for a matching KeyID.
            if( Password.IsSpecified )
            {
                // Use the command line password when searching.
                d->PasswordForSearching = Password.Value;
                
                // Print status message if verbose output is enabled.
                if( IsVerbose.Value )
                {
                    printf( "Looking for KeyID to decode header.\n" );
                }
            }
            else // No password was specified on the command line.
            {
                // Use default passwords when searching instead.
                d->PasswordForSearching = 0;
                
                // Print status message if verbose output is enabled.
                if( IsVerbose.Value )
                {
                    printf( "Looking for KeyID and password to decode header.\n" );
                }
            }
             
            // Find a key definition in a key map given the header of an OT7 
            // record and an optional password.
            LookupKeyDefinitionByOT7Header( 
                KeyMapList.Value, 
                    // A list of text strings read from a 'key.map' file. 
                    //
                d->PasswordForSearching,
                    // Password to use when searching, or 0 if default passwords
                    // should be used instead. Default passwords come from key
                    // definitions first, and then the application default
                    // password is tried next.
                    //
                d->Header,
                    // The header of an OT7 record to use when searching for a 
                    // match. This is a 24-byte field.
                    // 
                &d->TheKeyDefinition, 
                    // OUT: Either a reference to a text line of the matching key
                    //      definition, or 0 if no match was found. If a match is
                    //      found, then the KeyID is returned in FoundKeyID, the
                    //      password used in FoundPassword, and the KeyAddress
                    //      decoded from the header is returned in KeyAddress.
                    //
                &d->FoundKeyID,  
                    // OUT: FoundKeyID, the KeyID of the key definition found to
                    //      match the KeyIDHash in the OT7 header, or nothing is
                    //      returned if there was no match.
                    //
                &d->FoundPassword,
                    // OUT: The password found to successfully decrypt the header,
                    //      either PasswordForSearching, a password from the key
                    //      definition, or the default password. This is a
                    //      dynamically allocated copy of the password that will
                    //      need to be freed. Nothing is returned if no match was
                    //      found.
                    //
                &d->KeyAddress );
                    // OUT: The decoded KeyAddress from d->Header, or nothing is
                    //      returned if there was no match.
                        
            // If a key definition was found, then mark the KeyID as specified.
            if( d->TheKeyDefinition )
            {
                // Use the found KeyID as the decryption KeyID.
                KeyID.Value = d->FoundKeyID;
            
                // Mark the KeyID as having been specified.
                KeyID.IsSpecified = 1;
                
                // Replace the current password parameter string with the one 
                // found to decrypt the header.
                
                // First deallocate the current password string buffer.
                DeleteString( Password.Value );
                
                // Link the Password parameter to the password located by the
                // lookup routine.
                Password.Value = d->FoundPassword;
                
                // Now mark the found password address as zero since the 
                // Password parameter now owns the buffer. It will be freed
                // on application exit.
                d->FoundPassword = 0;
            }
        }
        
        // If a key definition was found, then use it to augment the command line
        // parameters.
        if( d->TheKeyDefinition )
        {
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Found key definition for KeyID %s.\n", 
                         ConvertIntegerToString64(KeyID.Value) );
            }

            // Augment the command line parameters from settings in the key
            // definition, but don't override any parameters given on the
            // command line.
            AugmentCommandLineParametersFromKeyDefinition( 
                KeyMapList.Value, d->TheKeyDefinition );
        }            
    }
    
    //--------------------------------------------------------------------------
    
    // If the KeyID is still not specified by this point, then the default KeyID
    // will be used when attempting to decode the header.
    if( KeyID.IsSpecified == 0 )
    {
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "Can't identify KeyID, using default value %s.\n",
                     ConvertIntegerToString64( KeyID.Value ) );
        }
    }
    
    //--------------------------------------------------------------------------
     
    // If no key file names have been specified yet, then generate a key file 
    // name from the KeyID number.
    if( KeyFileNames.IsSpecified == 0 )    
    {            
        // Use the default interpretation of the KeyID number, which is to 
        // convert it to a decimal number with the file extension '.key', eg. 
        // '4239832.key'. 
    
        // Construct a file name from the KeyID, treating it as a decimal
        // number.
        sprintf( d->KeyFileNameBuffer, "%s.key",
                 ConvertIntegerToString64( KeyID.Value ) );

        // Use the next parameter as the name of the one-time pad key file.
        // Append the file name to list of key files.
        InsertDataLastInList( 
            KeyFileNames.Value, 
            (u8*) DuplicateString( (s8*) d->KeyFileNameBuffer ) );    
            
        // Print status message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "Since no key file name has been specified, the KeyID " 
                    "has been used to make key file name '%s'.\n",
                    (s8*) d->KeyFileNameBuffer );
        }
        
        // Mark the key filename parameter has having been specified.
        KeyFileNames.IsSpecified = 1;
    }
    
    //--------------------------------------------------------------------------
    
    // If the KeyAddress has not yet been decoded from the header, do that next.
    if( d->KeyAddress == 0 )
    {
        // By this point Password.Value will hold the password to use for
        // decrypting the record. Initially Password.Value is set to 
        // DefaultPassword, but a password entered on the command line will 
        // override it. If no command line password is entered and a key 
        // definition is found, then a password in the key definition will 
        // override the DefaultPassword.

        // Compute the 16-byte hash that is used to encrypt the KeyID and 
        // KeyAddress.
        ComputeKeyIDHash128bit( 
            (u8*) &d->Header[HEADERKEY_FIELD_OFFSET],
                // The HeaderKey value of the OT7 record header. 
                // This is an 8-byte hash.
                //
            KeyID.Value, 
                // KeyID identifies a key definition by number.  
                //
            Password.Value,
                // Password to use when computing the hash.
                //
            d->KeyIDHash128bit );
                // OUT: Output buffer for the 128-bit hash produced.
                
        // If the KeyIDHash fields match, then decrypt the KeyAddress field.
        if( IsMatchingBytes( 
                (u8*) &d->Header[KEYIDHASH_FIELD_OFFSET],
                d->KeyIDHash128bit,
                KEYIDHASH_FIELD_SIZE ) )
        {
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Header matches given KeyID and password.\n" );
            }

            // Decode the KeyAddress field.
            
            // XOR the KeyAddress with the hash value in the KeyAddress field.
            XorBytes( &d->Header[KEYADDRESS_FIELD_OFFSET], // From 
                      &d->KeyIDHash128bit[8],              // To  
                      KEYADDRESS_FIELD_SIZE );             // ByteCount
            
            // Get the decoded KeyAddress.          
            d->KeyAddress = Get_u64_LSB_to_MSB( &d->KeyIDHash128bit[8] );
        }
        else // No KeyIDHash match, so fail with an error message.
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( 
                    "ERROR: Header doesn't match given KeyID and password.\n" );
            }

            // Set the result code to be returned when the application exits.
            Result = RESULT_CANT_IDENTIFY_KEYADDRESS_FOR_DECRYPTION;

            // Return from this routine, having failed to decode the header.
            return;
        }
    }
    
    // Print status message if verbose output is enabled.
    if( IsVerbose.Value )
    {
        printf( "KeyAddress = %s.\n",
                 ConvertIntegerToString64( d->KeyAddress ) );
    }
}

/*------------------------------------------------------------------------------
| IdentifyEncryptionKey
|-------------------------------------------------------------------------------
|
| PURPOSE: To identify an encryption key based on command line parameters.
|
| DESCRIPTION: This routine locates the encryption key information based on
| fully or partially qualified references to the key entered on the command
| line.
|
| Several options exist depending on what input was given on the command line. 
| The key file may be specified by name, or a reference to a key definition in 
| a 'key.map' file may be given via some sort of identifier (-KeyID or -ID 
| options).
|
| This routine fills in missing information not given on the command line by
| using data found in a 'key.map' file or by using default settings.
|
| HISTORY: 
|    08Mar14 From EncryptFileOT7().
------------------------------------------------------------------------------*/
void
IdentifyEncryptionKey( OT7Context* C )
{
    // If a key file has not been specified or if a KeyID has not been 
    // specified, then try to look up needed information in the 'key.map' file.
    if( (KeyFileNames.IsSpecified == 0) || (KeyID.IsSpecified == 0) )
    {
        // If a KeyID has not been specified and no '-ID' terms have been given,
        // then take the default KeyID as being specified.
        if( (KeyID.IsSpecified == 0) && (IDStrings.IsSpecified == 0) )
        {
            // Mark the KeyID as specified.
            KeyID.IsSpecified = 1;
            
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Using default KeyID %s.\n",
                        ConvertIntegerToString64( KeyID.Value ) );
            }
        }
        
        //----------------------------------------------------------------------
        
        // If a 'key.map' file has not yet been read into memory, then try to
        // read it into a linked list of text strings, stripping comments and
        // whitespace.
        if( KeyMapList.IsSpecified == 0 )
        {
            // Read the key map file as a list of strings, appending them to the
            // given list.  
            ReadKeyMap( 
                KeyMapFileName.Value, 
                    // File name string for the key map file, defaulting to
                    // 'key.map'.
                    //
                KeyMapList.Value );
                    // List to receive the contents of the key map when is read.
                    
            // If data was read from the key map file, then set the IsSpecified
            // flag to 1.
            if( KeyMapList.Value->ItemCount )
            {
                KeyMapList.IsSpecified = 1;
                
                // Print status message if verbose output is enabled.
                if( IsVerbose.Value )
                {
                    printf( "Read key map file '%s' into memory.\n", 
                             KeyMapFileName.Value );
                }
            }
        }
         
        // If able to read the key map file, then use a KeyID or IDStrings to
        // locate the key definition to use for encrypting the file if possible.
        if( KeyMapList.IsSpecified )
        {
            // If the KeyID is specified, then use it to look up a key 
            // definition.
            if( KeyID.IsSpecified )
            {
                // Find the item in the KeyMapList that refers to the beginning 
                // of a key definition that corresponds to KeyID, a line of text 
                // such as "KeyID( 1844 )" where the number identifies the key 
                // definition. 
                C->TheKeyDefinition = 
                    LookupKeyDefinitionByKeyID( KeyMapList.Value, KeyID.Value );
                        
                // If a key definition was found, then skip other ways to locate
                // a key definition.
                if( C->TheKeyDefinition )
                {
                    // Print status message if verbose output is enabled.
                    if( IsVerbose.Value )
                    {
                        printf( "Found key definition for KeyID %s.\n", 
                                 ConvertIntegerToString64(KeyID.Value) );
                    }

                    goto AfterKeyDefinitionLookup;
                }
            }
            
            // If any ID term is specified, then use it to look up a key 
            // definition.
            if( IDStrings.IsSpecified )
            {
                // Find the item in the KeyMapList that refers to the beginning 
                // of a key definition that corresponds to an ID string, a line 
                // of text such as "KeyID( 143 )" where the number is the
                // primary identifier for the key definition. Returns the KeyID  
                // in FoundKeyID. 
                C->TheKeyDefinition = 
                    LookupKeyDefinitionByIDStrings( 
                        KeyMapList.Value, 
                        IDStrings.Value,
                        &C->FoundKeyID );
                        
                // If a key definition was found, then skip other ways of locating
                // a key definition.
                if( C->TheKeyDefinition )
                {
                    // If the KeyID has not yet been specified, then use the 
                    // KeyID associated with the secondary identifier.
                    if( KeyID.IsSpecified == 0 )
                    {
                        // Use the KeyID associated with the secondary identifier
                        // supplied by the user.
                        KeyID.Value = C->FoundKeyID;
                    
                        // Mark the KeyID as indirectly specified via a 
                        // secondary identifier.
                        KeyID.IsSpecified = 1;
                    }
                    
                    // Print status message if verbose output is enabled.
                    if( IsVerbose.Value )
                    {
                        printf( "Found key definition for KeyID %s.\n", 
                                 ConvertIntegerToString64(KeyID.Value) );
                    }
                   
                    goto AfterKeyDefinitionLookup;
                }
            }
            
            // If this point is reached, then the attempt to locate a key file
            // in the 'key.map' file has failed. A key file name can still be
            // generated from the KeyID, so continue.
            
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "Can't find KeyID %s in key map.\n", 
                         ConvertIntegerToString64(KeyID.Value) );
            }
              
        } // if( KeyMapList )    
                 
    } // if( KeyFileNames.IsSpecified == 0 )

    //--------------------------------------------------------------------------
         
///////////////////////////    
AfterKeyDefinitionLookup://
///////////////////////////    
            
    // If a key definition was found, then use it to augment the command line
    // parameters.
    if( C->TheKeyDefinition )
    {
        // Augment the command line parameters from settings in the key
        // definition, but don't override any parameters given on the command
        // line.
        AugmentCommandLineParametersFromKeyDefinition( 
            KeyMapList.Value, C->TheKeyDefinition );
    }    
             
    //--------------------------------------------------------------------------

    // If no key file name has been specified but a KeyID has been specified,
    // then generate a key file name from the KeyID number.
    if( KeyFileNames.IsSpecified == 0 )    
    {            
        // Use the default interpretation of the KeyID number, which is to 
        // convert it to a decimal number with the file extension '.key', eg. 
        // '4239832.key'. 
    
        // Construct a file name from the KeyID, treating it as a decimal
        // number.
        sprintf( C->KeyFileNameBuffer, "%s.key",
                 ConvertIntegerToString64( KeyID.Value ) );

        // Use the next parameter as the name of the one-time pad key file.
        // Append the file name to the list of key files.
        InsertDataLastInList( 
            KeyFileNames.Value, 
            (u8*) DuplicateString( C->KeyFileNameBuffer ) );    
            
        // Print status message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "Made default key file name '%s' from KeyID.\n",
                    C->KeyFileNameBuffer );
        }
        
        // Mark the key filename parameter has having been specified.
        KeyFileNames.IsSpecified = 1;
    }
}

/*------------------------------------------------------------------------------
| InitializeApplication
|-------------------------------------------------------------------------------
|
| PURPOSE: To initialize the OT7 application.
|
| DESCRIPTION: Use this routine to prepare the application for parsing the
| command line. 
|
| HISTORY: 
|    27Oct13 
|    24Dec13 Revised to initialize parameters using lists.
|    19Jan14 Moved zero filling of command line parameters into 
|            ZeroAndFreeAllBuffers(). Renamed from ResetApplication().
------------------------------------------------------------------------------*/
void
InitializeApplication()
{
    u32 i;
    
    // Zero all application parameters and mark them as unspecified.
    InitializeParameters();
    
    // Zero all the working buffers and variables in the OT7 application.
    ZeroAndFreeAllBuffers();
     
    //--------------------------------------------------------------------------
    // Make an empty list record for each of the string list parameters. This
    // simplifies the addition of items to string lists later.
    
    // Start with the first item in the list of all string list parameters.
    i = 0;
    
    // Process each item in the table of all string list parameters. The table
    // is terminated with a zero.
    while( StringListParameters[i] )
    {
        // Initialize the parameter to be an empty list.
        StringListParameters[i]->Value = MakeList();
    
        // Advance to the next item in the table.
        i++;
    }
    
    //--------------------------------------------------------------------------
       
    // Set the default encoding format to base64 for the encrypted OT7 file.  
    // This can be changed to binary on the command line with the '-binary' 
    // option.
    EncryptedFileFormat.Value = OT7_FILE_FORMAT_BASE64;
    
    // Set the default verbose mode to be enabled.
    IsVerbose.Value = 1;  // <- Change this to zero to disable verbose mode
                          // by default.
    
    // In the following, dynamically allocate strings so that the string 
    // parameter cleanup routine can work in a consistent way.
    
    // Set the default name of the input file for the encryption operation
    // to be "plain.txt". 
    NameOfPlaintextFile.Value = DuplicateString( "plain.txt" );
    
    // Set the default name of the input file for the decryption operation
    // to be "ot7d.in". This is a file in OT7 format.
    NameOfEncryptedInputFile.Value = DuplicateString( "ot7d.in" );
      
    // Set the default name of the decrypted output file to be 'ot7d.out'. 
    NameOfDecryptedOutputFile.Value = DuplicateString( "ot7d.out" );
    
    // Set the default name of the encrypted output file to be "ot7e.out". 
    NameOfEncryptedOutputFile.Value = DuplicateString( "ot7e.out" );
           
    // Set the default password. 
    Password.Value = DuplicateString( DefaultPassword );
           
    // Set the default name of the 'key.map' file. This config file organizes 
    // the keys that are available for use. It is optional to use a key map 
    // file.
    KeyMapFileName.Value = DuplicateString( "key.map" );
           
    // Set the default name of the 'ot7.log' file. This file tracks used key
    // bytes.
    LogFileName.Value = DuplicateString( "ot7.log" );
}

/*------------------------------------------------------------------------------
| InitializeHashWithTrueRandomBytesAndPassword
|-------------------------------------------------------------------------------
|
| PURPOSE: To initialize a Skein1024 hash context using true random bytes and a
|          password. 
|
| DESCRIPTION: This routine reads true random bytes from the current location in
| the given key file and XOR's them with the password to make a hash context 
| that depends on both data sources.
|
| The total number of bytes fed into the hash context is the longer of the two
| data sources, being either TrueRandomByteCount or the length of the password.
|
| HISTORY: 
|    15Feb14 
|    19Feb14 Revised to XOR password bytes with true random bytes before feeding
|            into the hash function. This eliminates the possibility of password
|            leakage in the event some means is found to invert the hash 
|            function from many hash instances.
|    28Feb14 Moved computation of the number of true random bytes to be read to
|            this routine from higher level code. Fixed error in segmentation of
|            password code.
|    17Mar14 Revised to use OT7Context record as a parameter.
------------------------------------------------------------------------------*/
    // OUT: Result code: RESULT_OK on success, or an error code on failure.
u32 //
InitializeHashWithTrueRandomBytesAndPassword( 
    OT7Context* c,
        // Context of a file in the process of being encrypted or decrypted.
        //
    Skein1024Context* HashContext,
        // Hash context to be initialized.
        //
    u32 HashSizeInBits,
        // Size of the hash to be produced in bits.
        //
    s8* Password )
        // The password string to feed into the hash context.
{
    u32 i;
    u32 j;
    u32 result;
    u32 BytesRead;
    u32 BytesToReadThisPass;
    u32 PasswordBytesToHash;
    u32 PasswordBytesToHashThisPass;
    u32 TrueRandomBytesToHash;
    
    // Measure the length of the password string, not counting the terminal
    // zero.
    PasswordBytesToHash = CountString( Password );
    
    // Use at least one true random key byte for each byte of the password to
    // avoid leaking password information.
    TrueRandomBytesToHash = PasswordBytesToHash;
    
    // Use a minimum of MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT bytes to cover
    // the case where a short password is used. The goal is to make it hard
    // for an attacker to guess the initial state of the password hash 
    // context.
    if( TrueRandomBytesToHash < MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT )
    {
        TrueRandomBytesToHash = MIN_TRUE_RANDOM_BYTES_FOR_HASH_INIT;
    }
 
    // Initialize the hash context for producing a hash of a given size.
    Skein1024_Init( HashContext, HashSizeInBits );
    
    // Use 'i' to refer to the next password byte to hash, starting with the 
    // first.
    i = 0;
    
    // Continue as long as true random bytes and/or password bytes remain to be 
    // fed into the hash context. TrueRandomBytesToHash will always be >=
    // PasswordBytesToHash.
    while( TrueRandomBytesToHash )
    {
        // If the number of remaining key bytes to read is larger than the size
        // of the key buffer, then limit the number read to the size of the key
        // buffer.
        if( TrueRandomBytesToHash > KEY_BUFFER_SIZE )
        {
            BytesToReadThisPass = KEY_BUFFER_SIZE;
        }
        else // All of the remaining bytes can be read into the buffer.
        {
            BytesToReadThisPass = TrueRandomBytesToHash;
        }
         
        // If the number of password bytes left to hash is more than the size
        // of the key buffer, then limit the number of bytes to hash to the 
        // size of the key buffer.
        if( PasswordBytesToHash > KEY_BUFFER_SIZE )
        {
            PasswordBytesToHashThisPass = KEY_BUFFER_SIZE;
        }
        else // All of the remaining password bytes can be hashed on this pass.
        {
            PasswordBytesToHashThisPass = PasswordBytesToHash;
        }
         
        // If bytes should be read from the key file, then do it.
        if( BytesToReadThisPass )
        {      
            // Read a block of key bytes to the TrueRandomKeyBuffer.
            BytesRead = ReadBytes( c->KeyFileHandle, 
                                   c->TrueRandomKeyBuffer,
                                   BytesToReadThisPass );

            // If the key file could not be read, then return with an error  
            // message.
            if( BytesRead != BytesToReadThisPass )
            {
                // Fail, returning an error code.
                result = RESULT_CANT_READ_KEY_FILE;
    
                // Clean up the working buffers and return the error code.
                goto CleanUp;
            }
        }

        // If password bytes should be added to the hash this pass, then merge
        // some into the key buffer.
        if( PasswordBytesToHashThisPass )
        {
            // XOR the password with any key bytes in the key buffer.
            for( j = 0; j < PasswordBytesToHashThisPass; j++ )
            {
                // XOR a password byte with the contents of the key buffer.
                c->TrueRandomKeyBuffer[j] ^= Password[i];
                
                // Advance to the next byte of the password.
                i++;
            }
        }
        
        // The number of bytes to hash this pass is the same as the number of
        // true random bytes read on this pass. This number will always be at
        // least as long or longer than the number of pasword bytes added to
        // the key buffer.
        
        // Feed the contents of the key buffer into the hash context.
        Skein1024_Update( 
            HashContext, 
            c->TrueRandomKeyBuffer, 
            BytesToReadThisPass );
              
        // Reduce the number of true bytes to be read by the number that were
        // read on this pass.
        TrueRandomBytesToHash -= BytesToReadThisPass;
        
        // Reduce the number of password bytes to be hashed by the number 
        // hashed on this pass.
        PasswordBytesToHash -= PasswordBytesToHashThisPass;
    }
    
    // At this point the hash context has been initialized properly.
    result = RESULT_OK;

//////////    
CleanUp://
////////// 
   
    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential
    // for information leakage.
    //--------------------------------------------------------------------------
    
    // Erase the key bytes from the true random key buffer.
    ZeroBytes( c->TrueRandomKeyBuffer, KEY_BUFFER_SIZE );
    
    // Zero the local variables.
    i = 0;
    j = 0;
    result = 0;
    BytesRead = 0;
    BytesToReadThisPass = 0;
    PasswordBytesToHash = 0;
    PasswordBytesToHashThisPass = 0;
    TrueRandomBytesToHash = 0;

    // Zero all of the stack locations used to pass parameters into this
    // routine.
    HashContext = 0;
    HashSizeInBits = 0;
    TrueRandomBytesToHash = 0;
    Password = 0;
        // Only the address of the password string is cleared, the password 
        // string remains unchanged in the buffer that holds it.
           
    // Return RESULT_OK for success, or an error code.
    return( result );
}
        
/*------------------------------------------------------------------------------
| InitializeParameters
|-------------------------------------------------------------------------------
|
| PURPOSE: To initialize all application parameters.
|
| DESCRIPTION: Use this routine to initialize the IsSpecified field of 
| parameters to the unspecified (0) state prior to being used for the first
| time. Also sets the Value field to 0, a generic default value.
|
| Use ZeroAndFreeAllBuffers() to clean up parameters after use.
|
| HISTORY: 
|    19Jan14 From InitializeApplication().
|    21Feb14 Revised to use ZeroAllNumericParameters(), 
|            ZeroAllStringParameters(), and ZeroAllStringListParameters().
------------------------------------------------------------------------------*/
void
InitializeParameters()
{
    // Zero all numeric parameters, marking them as unspecified.
    ZeroAllNumericParameters();
     
    // Zero all string parameters, marking them as unspecified.
    ZeroAllStringParameters();
     
    // Zero all string list parameters, marking them as unspecified. 
    ZeroAllStringListParameters();
}

/*------------------------------------------------------------------------------
| InsertDataLastInList
|-------------------------------------------------------------------------------
|
| PURPOSE: To put a given data address into a new Item record, and append it to
|          a list.
|
| DESCRIPTION: Makes a generic Item record capable of pointing to data of any 
| kind, at any address in memory. 
|
| The data at the SomeData address is not modified by this routine. 
|
| EXAMPLE:  
|                 NewItem = InsertDataLastInList(L, SomeData);
| HISTORY: 
|    09Jan88
|    17Nov13 Revised comments, handled allocation error.
------------------------------------------------------------------------------*/
        // OUT: Address of a new Item record that refers to the given data, or
        //      0 if unable to allocate a new Item record.
Item*   //
InsertDataLastInList( List* L, u8* SomeData )
{
    Item* AnItem;
 
     // Allocate a new Item record that refers to the address given in SomeData.
    AnItem = MakeItemForData( SomeData );
    
    // If an Item record was allocated, then append it to the list.
    if( AnItem )
    {
        // Append the Item record to the list.
        InsertItemLastInList( L, AnItem );
    }
 
     // Return the address of the new Item record, or 0 if unable to allocate a 
     // new Item record.
    return( AnItem );
}

/*------------------------------------------------------------------------------
| InsertItemLastInList
|-------------------------------------------------------------------------------
|
| PURPOSE: To append the given extracted item to a list.
|
| DESCRIPTION:
|
| EXAMPLE:           InsertItemLastInList( L, ItemToInsert );
|
| HISTORY: 09Jan88
------------------------------------------------------------------------------*/
void
InsertItemLastInList( List* L, Item* AnItem )
{
    Item* LastItem;
    
    // Mark the item to be inserted into the list as last in the list.
    MarkItemAsLast( AnItem );
    
    // If the list contains any items, then handle that case.
    if( IsAnyItemsInList(L) ) 
    {
        // Get the address of the current last item.
        LastItem = L->LastItem;
        
        // Link the new item to the old last item.
        AnItem->PriorItem = LastItem;
        
        // Link the old last item to the new last item.
        LastItem->NextItem = AnItem;
    }
    else // There are no items in the list.
    {
        // Mark the item to be inserted into the list as first as well as
        // last.
        MarkItemAsFirst( AnItem );
        
        // Link the list record to the item record using the FirstItem field.
        L->FirstItem = AnItem;
    }
    
    // Link the list record to the item record using the LastItem field.
    L->LastItem = AnItem;
    
    // Increment the list's item counter to account for appending an item.
       L->ItemCount++;
}

/*------------------------------------------------------------------------------
| InterleaveTextFillBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To interleave text and fill bytes to the TextFillBuffer.
|
| DESCRIPTION: This routine manages the ordering of bytes being written to the
| TextFill field of an OT7 record.
|
| The source of text and fill bytes are the TextBuffer and FillBuffer in the
| given OT7Context record.
|
| The destination is the TextFillBuffer in the same context record.
|
| The number and ordering of bytes to be interleaved depends on the current
| state of the context record.
|
| See also DeinterleaveTextFillBytes() which reverses the process of this 
| routine.
|
| HISTORY: 
|    09Mar14 From EncryptOT7().
------------------------------------------------------------------------------*/
void
InterleaveTextFillBytes( OT7Context* e )
{
    u32 i;
    u32 t;
    u32 f;
            
    // Start with no text bytes interleaved by setting t to 0.
    t = 0;

    // Start with no fill bytes interleaved by setting f to 0.
    f = 0;
        
    // Interleave a block of text and/or fill bytes.
    for( i = 0; i < e->BytesToWriteThisPass; i++ )
    {
        // If a text byte should be placed next in the TextFill buffer, and text 
        // bytes remain to be encrypted, then move one text byte.
        if( e->IsTextByteNext && (t < e->TextBytesToWriteThisPass) )
        {
            // Copy one byte from the TextBuffer to the TextFillBuffer.
            e->TextFillBuffer[i] = e->TextBuffer[t];
            
            // Account for moving the text byte by incrementing t.
            t++;
            
            // If fill bytes remain to be encrypted, then select a fill byte 
            // next.
            if( f < e->FillBytesToWriteThisPass )
            {
                e->IsTextByteNext = 0;
            }
        } 
        else // A fill byte should be placed next.
        {
            // Copy one byte from the FillBuffer to the TextFillBuffer.
            e->TextFillBuffer[i] = e->FillBuffer[f];
             
            // Account for inserting the fill byte by incrementing f.
            f++;
            
            // If text bytes remain to be interleaved, then select a text byte 
            // next.
            if( t < e->TextBytesToWriteThisPass )
            {
                e->IsTextByteNext = 1;
            }
        }
    }
    
    // Clean up by clearing local variables.
    i = 0;
    t = 0;
    f = 0;
}

/*------------------------------------------------------------------------------
| IsAnyItemsInList
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if a list has any items.
|
| DESCRIPTION: Returns non-zero if the list contains any items.
|
| EXAMPLE:               Result = IsAnyItemsInList( L );
|
| HISTORY: 
|    05Jan88
------------------------------------------------------------------------------*/
    // OUT: Non-zero if the list contains items, or 0 if not.
u32 //
IsAnyItemsInList( List* L )
{
    return( (u32) L->ItemCount );
}

/*------------------------------------------------------------------------------
| IsItemAlone
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if an item is the only one in a list.
|
| DESCRIPTION: If both PriorItem and NextItem are 0, then the item is the only 
| one in a list.
|
| EXAMPLE:  if( IsItemAlone(AnItem) ) return(1);
|
| HISTORY: 
|    04Jan88
|    12Jul89 revised
|    29Nov13 Made test more direct and easier to understand.
------------------------------------------------------------------------------*/
u32  
IsItemAlone( Item* AnItem )
{
    // If the item is both first and last, then it is the only item in the list.
    return( (AnItem->PriorItem == 0) && (AnItem->NextItem == 0) );
}

/*------------------------------------------------------------------------------
| IsItemFirst
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if an item is first in a list.
|
| DESCRIPTION: If PriorItem is 0 then it is the first item.
|
| EXAMPLE:  if( IsItemFirst(AnItem) ) return(1);
|
| HISTORY: 
|    04Jan88
|    20Jan02 Changed from !AnItem->PriorItem.
------------------------------------------------------------------------------*/
u32  
IsItemFirst( Item* AnItem )
{
    return( AnItem->PriorItem == 0 );
}

/*------------------------------------------------------------------------------
| IsItemLast
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if an item is last in a list.
|
| DESCRIPTION: If NextItem is 0 then it is the last item.
|
| EXAMPLE:  if( IsItemLast(AnItem) ) return(1);
|
| HISTORY: 
|    04Jan88
|    31Dec01 Expanded macro.
------------------------------------------------------------------------------*/
u32  
IsItemLast( Item* AnItem )
{
    return( AnItem->NextItem == 0 );
}

/*------------------------------------------------------------------------------
| IsFileNameValid
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if a file name is valid.
|
| DESCRIPTION: This routine tests bytes in a buffer to see if they qualify as a
| valid file name. Only printable ASCII characters and spaces are allowed, and
| the whole string must be less than MAX_FILE_NAME_SIZE bytes.
|
| HISTORY:  
|    30Nov13
------------------------------------------------------------------------------*/
    // OUT: 1 if the file name is valid, or 0 if not.
u32 //
IsFileNameValid( s8* FileName )
{
    s8  b;
    u32 Size;
    
    // Reject invalid buffer addresses.
    if( FileName == 0 )
    {
        return( 0 );
    }
    
    // Start the length of the file name at zero.
    Size = 0;
     
    // Scan through the file name string until the first 0 byte.

//////////
GetByte://
//////////
    
    // Get a byte and advance the byte cursor.
    b = *FileName++;
    
    // If the end of the string has not been reached, then test the character
    // to see if it is printable ASCII or a space.
    if( b )
    {
        // If b is printable ASCII or a space, then continue scanning.
        if( IsPrintableASCIICharacter(b) )
        {
            // Increment the byte counter.
            Size++;
            
            // Go fetch the next byte and check it.
            goto GetByte;
        } 
        else // An out-of-bounds byte.
        {
            // Return 0 to mean the file name is invalid.
            return( 0 );
        }
    }
    
    // The end of the string has been reached by finding a zero byte.
    
    // If the size of the string plus the string terminator byte is larger than
    // the maximum supported file name size, then return 0.
    if( (Size+1) > MAX_FILE_NAME_SIZE )
    {
        // Return 0 to mean the file name is invalid.
        return( 0 );
    }
      
    // Return 1 to mean the file name is valid.
    return( 1 );
}

/*------------------------------------------------------------------------------
| IsMatchingBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if two blocks of memory match in value.
|
| DESCRIPTION: Returns 1 if they match, or 0 if not.
|
| HISTORY: 
|    21Oct89
|    15Feb93 changed count to quad.
|    03Mar99 Sped up.
|    16Jun01 Added test for quad alignment before using quad comparisons and 
|            added middle byte comparison test.
|    01Mar14 Removed 4-bytes-at-a-time comparison due to portability problems:
|            fix this later to improve performance.  
------------------------------------------------------------------------------*/
    // OUT: Returns 1 if block A matches block B in value, or 0 if not.
u32 //
IsMatchingBytes( u8* A, u8* B, u32 Count )
{
    u32 m;
    
    // Calculate the index of the middle byte of the blocks.
    m = Count >> 1;
    
    // If the middle byte of the blocks differ, then return a mismatch.
    // This generally improves performance.
    if( A[ m ] != B[ m ] )
    {
        // Return a mismatch.
        return( 0 );
    }
    
    // If the blocks start at the same place, then they match.
    if( A == B )
    {
        return( 1 ); 
    }
    
    // Compare any remaining bytes one by one.
    while( Count-- )
    {
        // If the bytes differ.
        if( *A++ != *B++ )
        {
            // Return zero to signal a mismatch.
            return( 0 );
        }
    }
    
    // Return a match if no mismatch occurs above.
    return( 1 );         
}

/*------------------------------------------------------------------------------
| IsMatchingStrings
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if two zero-terminated strings match in value.
|
| DESCRIPTION: Returns 1 if they match, or 0 if not.
|
| HISTORY: 
|    01Mar14 From IsMatchingBytes().
------------------------------------------------------------------------------*/
    // OUT: Returns 1 if string A matches block B in value, or 0 if not.
u32 //
IsMatchingStrings( s8* A, s8* B )
{
    // If A and B have the same address, then they match.
    if( A == B )
    {
        // Return 1 to mean that the strings match.
        return(1);
    }

///////////////
CompareBytes://
///////////////
    
    // Compare corresponding bytes from each string, returning 0 if they differ.
    if( *A != *B )
    {
        // If the current bytes in the strings don't match, then return 0 to
        // mean that the strings don't match.
        return(0);
    }
    
    // If the ends of both strings have been reached together, then return 1 to 
    // mean that the strings have the same value.
    if( (*A == 0) && (*B == 0) )
    {
        return(1);
    }
    
    // Advance to the next byte of string A.
    A++;
    
    // Advance to the next byte of string B.
    B++;
    
    // Go compare the new current bytes.
    goto CompareBytes;
}
  
/*------------------------------------------------------------------------------
| IsPrefixForString
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if one string is the prefix for another.
|
| DESCRIPTION: This is a string comparison operation. Strings are compared until 
| the end of prefix string or until an in-equality is detected.
|
| Returns: 1 if the prefix string matches the beginning of the other string, or
| returns 0 if not.
|
| Strings must be zero-terminated for this routine to work.
|
| HISTORY:  
|    04Apr91 
|    22Sep93 added 1/0, changed for() to while()
|    27Nov13 Revised comments and changed from case-insensitive to be 
|            case sensitive.
------------------------------------------------------------------------------*/
    // OUT: 1 if the prefix string matches the other string over the entire
    //      length of the prefix string, or returns 0 if not.
u32 //
IsPrefixForString( s8* Prefix, s8* OtherString )
{
    while(1)
    {
        // If the end of the prefix string has been reached, then a match has
        // been found.
        if(*Prefix == 0)
        {
            // Return 1 to mean that the prefix matches the beginning of the
            // other string.
            return( 1 );  
        }
               
        // If the current byte of the prefix string doesn't match the 
        // corresponding byte of the other string, then return 0 to indicated
        // that a match was not found.
        if( *Prefix != *OtherString )
        {
             return( 0 );  
        }
            
        // Advance to the next byte of the prefix string.    
        Prefix++;
        
        // Advance to the next byte of the other string.
        OtherString++;
    }
}

/*------------------------------------------------------------------------------
| LookupKeyDefinitionByIDStrings
|-------------------------------------------------------------------------------
|
| PURPOSE: To find a key definition in a key map given one or more identifiers 
|          associated with a key definition. 
|
| DESCRIPTION: This routine scans the given key map list for a text string that
| matches any of the identifiers in the given IDStrings list.
|
| On exit from this routine the return value is either a reference to a text 
| line matching the first line of a key definition, or 0 is returned if no 
| match was found. If a match is found, then the KeyID is returned in
| FoundKeyID.
|
| A key definition has this form:
|
|     KeyID( 123 ) <=== The address of this line would be returned if a
|     {                 matching identifier is found in the body of the
|                       definition.
|
|           -ID an.example@identifier.net    <=== Strings such as these are
|           -ID 'Dan Jones'                 <=== what this routine looks for.
|
|           ...other parameters of the key definition...
|     }
|
| where:
|
|     '-ID an.example.identifier' is an identifier associated with the
|           key definition defined by KeyID 123.
|
|     '123' is the KeyID number of the key definition.
|
| HISTORY: 
|    18Jan14 From LookupKeyDefinitionByKeyID().
------------------------------------------------------------------------------*/
      // OUT: Either a reference to a text line matching the key definition, or 
      // 0 if no match was found. If a match is found, then the KeyID is   
      // is returned in FoundKeyID.
Item* //
LookupKeyDefinitionByIDStrings( 
    List* KeyMapList, 
             // A list of text strings read from a 'key.map' file. This list has
             // been preprocessed to strip out comments and any whitespace at 
             // both ends of the strings.
             //
     List* IDStringsList,
             // The identifier(s) to match when looking for a key definition.
             // This is a list of strings passed to the application using the 
             // '-ID' parameter on the command line. Normally this would be just 
             // one string, but more than one can be given for the same key 
             // definition too. The strings in this list are zero terminated
             // ASCII strings such as "an.example@identifier.net" or 
             // "Dan Jones": the '-ID' prefix used on the command line is not 
             // included.
             // 
    u64* FoundKeyID )
             // OUT: The KeyID  of the key definition found.
{
    ThatItem ID;
    ThatItem KM;
    s8* AtIDTag;
    s8* AtIdentifier;
    s8* AtKeyID;
    u32 ParseResult;
     
    // Refer to the first item in the ID strings list using cursor ID.
    ToFirstItem( IDStringsList, &ID ); 
    
    // Scan the ID strings list to the end or until a match is found.
    while( ID.TheItem )    
    {
        // Refer to the first item in the key map list using cursor KM.
        ToFirstItem( KeyMapList, &KM ); 
    
        // Scan the key map list to the end or until a match is found.
        while( KM.TheItem )    
        {
            // Scan the current text line for the identifier string.
            // Returns the address of the identifier in the string, or 0 if not 
            // found.
            AtIdentifier = 
                FindStringInString( 
                    (s8*) ID.TheItem->DataAddress, 
                    (s8*) KM.TheItem->DataAddress );
    
            // If the identifier was found, then test for the presence of '-ID' 
            // in the same line prior to identifier.
            if( AtIdentifier )
            {
                // This is the situation:
                //
                //     AtIdentifier
                //          |
                //          v
                //     -ID 'danjones@privatemail.net'
                
                 // Scan the current text line for the '-ID' string.
                // Returns the address of '-ID' in the string, or 0 if not 
                // found.
                AtIDTag = 
                    FindStringInString( 
                        "-ID", 
                        (s8*) KM.TheItem->DataAddress );
           
                   // If '-ID' was found before the identifier, then scan  
                   // backward through the key map list for the first line that 
                   // contains 'KeyID'.
                   if( AtIDTag && (AtIDTag < AtIdentifier) )
                   {
                        // Scan the key map list backward to the beginning or  
                        // until 'KeyID' is found.
                        while( KM.TheItem )    
                        {
                            // Step backward to the prior string in the key map 
                            // list.
                            ToPriorItem( &KM );
                               
                            // Scan the current text line for the 'KeyID' 
                            // string. Returns the address of 'KeyID' in the 
                            // string, or 0 if not found.
                            AtKeyID = 
                                FindStringInString( 
                                    "KeyID", 
                                    (s8*) KM.TheItem->DataAddress );
           
                           // If 'KeyID' was found at the beginning of the 
                           // string, then parse out the KeyID number. This test 
                           // depends on leading whitespace having been removed 
                           // from strings in the 'key.map' file after it has 
                           // been read in to memory.
                           if( AtKeyID && 
                               (AtKeyID == (s8*) KM.TheItem->DataAddress) )
                           {
                                // Parse the number from the key definition 
                                // string.
                                //
                                // OUT: Result code: RESULT_OK on success, or 
                                //      an error code otherwise.
                               ParseResult =
                                   ParseKeyIDFromKeyDefString( 
                                       AtKeyID,
                                       FoundKeyID );
                            
                                // If parsing was successful, return the address 
                                // of the Item record that refers to the KeyID
                                // string that begins the key definition.
                                if( ParseResult == RESULT_OK )
                                {    
                                    // Return the Item address of the first 
                                    // line of the key definition.
                                    return( KM.TheItem );
                                }
                           }
  
                       } // while( KM.TheItem ) 
                       
                   } // if( AtIDTag && (AtIDTag < AtIdentifier) )
                   
               } // if( AtIdentifier )

            // Advance the item cursor to the next string in the key map list.
            ToNextItem(&KM);
        }
        
        // The end of the key map list has been reached without finding a 
        // match for the current identifier string.
        
        // Advance to the next identifier string in the list of identifiers.
        ToNextItem(&ID);
    }
    
    // Return 0 to mean that no matching definition was found.    
    return( 0 );
}              

/*------------------------------------------------------------------------------
| LookupKeyDefinitionByKeyID
|-------------------------------------------------------------------------------
|
| PURPOSE: To use a KeyID to find a key definition in a key map.  
|
| DESCRIPTION: This routine scans the given key map list for a text string that
| matches the given KeyID, a line of text such as "KeyID( 1844 )" where the 
| number identifies the key definition.
|
| On exit from this routine the return value is either a reference to a text 
| line matching the key definition, or 0 is returned if no match was found.  
|
| A key definition has this form:
|
|    KeyID( 1844 )
|    {
|          ...the parameters of the key...
|    }
|
| where:
|
|    '1844' is the KeyID number of the key definition, a unique identifier 
|           within the 'key.map' file.
|
|    KeyID numbers can be expressed in decimal or in hexadecimal form, eg. 
|    "KeyID( 0x41ad9 )". Values can range from 0 to the largest value that 
|    can be stored in a 64-bit field, 18446744073709551616 or 
|    0xFFFFFFFFFFFFFFFF.
|
| HISTORY: 
|    01Dec13 
|    16Feb14 Revised for hash-based header design.
------------------------------------------------------------------------------*/
      // OUT: Either a reference to a text line matching the key definition, or 
      // 0 if no match was found.  
Item* //
LookupKeyDefinitionByKeyID( 
    List* KeyMapList, 
             // A list of text strings read from a 'key.map' file. This list has
             // been preprocessed to strip out comments and any whitespace at 
             // both ends of the strings.
             //
    u64 KeyID )
            // The KeyID to match when looking for a key definition.
{
    ThatItem C;
    s8* S;
    u32 ParseResult;
    u64 ParsedKeyID;

    // Refer to the first item in the list using cursor C.
    ToFirstItem( KeyMapList, &C ); 
    
    // Scan the list to the end or until a match is found.
    while( C.TheItem )    
    {
        // Scan the current text line for the string 'KeyID'.
        // Returns the address of 'KeyID' in the string, or 0 if not found.
        S = FindStringInString( "KeyID", (s8*) C.TheItem->DataAddress );
    
        // If 'KeyID' was found, then test for a match with the given KeyID
        // number.
        if( S )
        {
            // This is the situation:
            //
            //     S
            //     |
            //     v
            //     KeyID( 1844 )
  
            // Parse the number from the key definition string.
            //
            // OUT: Result code: RESULT_OK on success, or an error code 
            //      otherwise.
            ParseResult =
                ParseKeyIDFromKeyDefString( 
                    S, // A string beginning with 'KeyID', such as 
                       // "KeyID( 1844 )". The string is zero-terminated ASCII.
                       //
                    &ParsedKeyID );
                       // OUT: Value parsed, eg. "1844" as a binary number.
  
             // If a value was successfully parsed, then check for a match.
             if( ParseResult == RESULT_OK )
             {
                // If the KeyID matches the key definition, then return the 
                // Item address of the first line of the definition.
                if( ParsedKeyID == KeyID )
                {
                    // Return the Item address of the first line of the 
                    // definition.
                    return( C.TheItem );
                }
            }
        }

///////////
NextLine://
///////////
          
        // Advance the item cursor to the next item in the list.           
        ToNextItem(&C);
    }
    
    // Return 0 to mean that no matching definition was found.    
    return( 0 );
}
              
/*------------------------------------------------------------------------------
| LookupKeyDefinitionByOT7Header
|-------------------------------------------------------------------------------
|
| PURPOSE: To find a key definition in a key map given the header of an OT7 
|          record and an optional password.
|
| DESCRIPTION: Decryption of an OT7 record involves a trial-and-error process of 
| trying all known (KeyID, Password) pairs with the HeaderKey from an OT7 record 
| until a matching KeyIDHash value is found. 
|    
| Input parameter OT7HeaderToMatch is the address of a header record, as shown
| here:
|                                H E A D E R                            
|                   --------------------------------------  
|                   | HeaderKey | KeyIDHash | KeyAddress |  
|                   ------------+-----------+------------+ 
|                   0           8          16           24                             
|                   |             
|                   OT7HeaderToMatch
|
| Input parameter KeyMapList is a list of key definitions.
|
| A key definition has this form:
|
|     KeyID( 123 ) <=== The address of this line would be returned if a
|     {                 matching definition is found for OT7HeaderToMatch.
|
|        -p "this is the password"  <=== Password in a key definition.
|
|        ...other parameters of the key definition...
|     }
|
| where:
|
|      123 is the KeyID number of the key definition.
|
|      -p "this is the password" is the password for key definition 123. 
|          It is optional to assign a password to a key definition.
|
| HISTORY: 
|    18Feb14 From LookupKeyDefinitionByIDStrings().
------------------------------------------------------------------------------*/
void
LookupKeyDefinitionByOT7Header( 
    List* KeyMapList, 
            // A list of text strings read from a 'key.map' file. This list has 
            // been preprocessed to strip out comments and any whitespace at 
            // both ends of the strings.
            //
    s8* PasswordForSearching,
            // Password to use when searching, or 0 if default passwords should 
            // be used instead. Default passwords come from key definitions 
            // first, and then the application default password is tried next.
            //
    u8* OT7HeaderToMatch,
            // The header of an OT7 record to use when searching for a match.
            // This is a 24-byte field.
            // 
    Item** KeyDefinition, 
            // OUT: Either a reference to a text line of the matching key 
            //      definition, or 0 if no match was found. If a match is found, 
            //      then the KeyID is returned in FoundKeyID, the password 
            //      used in FoundPassword, and the KeyAddress decoded from the 
            //      header is returned in KeyAddress.
            //
    u64* FoundKeyID,
            // OUT: The KeyID of the key definition found to match the
            //      KeyIDHash in the OT7 header, or nothing is returned if 
            //      there was no match.
            //
    s8** FoundPassword,
            // OUT: The password found to successfully decrypt the header,
            //      either PasswordForSearching, a password from the key
            //      definition, or the default password. This is a dynamically
            //      allocated copy of the password that will need to be freed.
            //      Nothing is returned if no match was found.
            //
    u64* KeyAddress )
            // OUT: The decoded KeyAddress from OT7HeaderToMatch, or nothing
            //      is returned if there was no match.
{
    static ThatItem C;
    static u8 KeyIDHash128bit[KEYIDHASH128BIT_BYTE_COUNT];
    static s8* KeyPassword;
    static s8* PasswordToReturn;
    static u32 ParseResult;
    static u64 ParsedKeyID;
    static s8* S;
                // Static buffers are used to save stack space.
     
    // Refer to the first item in the list using cursor C.
    ToFirstItem( KeyMapList, &C ); 
    
    // Scan the list to the end or until a match is found.
    while( C.TheItem )    
    {
        // Scan the current text line for the string 'KeyID'.
        // Returns the address of 'KeyID' in the string, or 0 if not found.
        S = FindStringInString( "KeyID", (s8*) C.TheItem->DataAddress );
    
        // If 'KeyID' was found, then test for a match with the given KeyID
        // number.
        if( S )
        {
            // This is the situation:
            //
            //     S
            //     |
            //     v
            //     KeyID( 1844 )
  
            // Parse the number from the key definition string.
            //
            // OUT: Result code: RESULT_OK on success, or an error code 
            //      otherwise.
            ParseResult =
                ParseKeyIDFromKeyDefString( 
                    S, // A string beginning with 'KeyID', such as 
                       // "KeyID( 1844 )". The string is zero-terminated ASCII.
                       //
                    &ParsedKeyID );
                       // OUT: Value parsed, eg. "1844" as a binary number.
  
            // If a value was successfully parsed, then check for a match.
            if( ParseResult == RESULT_OK )
            {
                //--------------------------------------------------------------
                // TRY SPECIFIC PASSWORD
                //--------------------------------------------------------------
                
                // If a specific password has should be used for searching, then
                // try for a match using with that password and the current
                // KeyID.
                if( PasswordForSearching )
                {
                    // Compute the 16-byte hash that is used to encrypt the 
                    // KeyID and KeyAddress.
                    ComputeKeyIDHash128bit( 
                        OT7HeaderToMatch,
                            // The HeaderKey value of an OT7 record header. 
                            // This is an 8-byte hash.
                            //
                        ParsedKeyID, 
                            // KeyID identifies a key definition by number.  
                            //
                        PasswordForSearching,
                            // Password to use when computing the hash.
                            //
                        (u8*) &KeyIDHash128bit[0] );
                            // OUT: Output buffer for the 128-bit hash produced 
                            //      by this function.
                            
                    // If the KeyIDHash fields match, then go return the found
                    // information.
                    if( IsMatchingBytes( 
                            (u8*) &OT7HeaderToMatch[KEYIDHASH_FIELD_OFFSET],
                            (u8*) &KeyIDHash128bit[0],
                            KEYIDHASH_FIELD_SIZE ) )
                    {
                        // Make a return copy of the input password string.
                        PasswordToReturn = 
                            DuplicateString( PasswordForSearching );
                            
                        goto ReturnFoundInfo;
                    }
                    else // No match, so try the next definition.
                    {
                        goto TryNextDefinition;
                    }
                }
                
                //--------------------------------------------------------------
                // TRY KEY DEFINITION PASSWORD
                //--------------------------------------------------------------
                 
                // Scan forward to see if there is a password in the current
                // definition. Returns a dynamically allocated copy of the
                // password.
                KeyPassword = 
                    FindPasswordInKeyDefinition( C.TheList, C.TheItem );
                
                // If there is a password in the definition, then try for a
                // match using that password and the current KeyID.
                if( KeyPassword )
                {
                    // Compute the 16-byte hash that is used to encrypt the 
                    // KeyID and KeyAddress.
                    ComputeKeyIDHash128bit( 
                        OT7HeaderToMatch,
                            // The HeaderKey value of an OT7 record header. 
                            // This is an 8-byte hash.
                            //
                        ParsedKeyID, 
                            // KeyID identifies a key definition by number.  
                            //
                        KeyPassword,
                            // Password to use when computing the hash.
                            //
                        (u8*) &KeyIDHash128bit[0] );
                            // OUT: Output buffer for the 128-bit hash produced 
                            //      by this function.
                             
                    // If the KeyIDHash fields match, then go return the found
                    // information.
                    if( IsMatchingBytes( 
                            (u8*) &OT7HeaderToMatch[KEYIDHASH_FIELD_OFFSET],
                            (u8*) &KeyIDHash128bit[0],
                            KEYIDHASH_FIELD_SIZE ) )
                    {
                        // Use the password copied from the key definition as 
                        // one to return.
                        PasswordToReturn = KeyPassword;
                             
                        goto ReturnFoundInfo;
                    }
                    else // No match, so try the next definition.
                    {
                        // Zero and deallocate the password string copied from  
                        // the definition.
                        DeleteString( KeyPassword );
                        
                        goto TryNextDefinition;
                    }
                }
                
                //--------------------------------------------------------------
                // TRY DEFAULT PASSWORD
                //--------------------------------------------------------------
                 
                // Compute the 16-byte hash that is used to encrypt the 
                // KeyID and KeyAddress.
                ComputeKeyIDHash128bit( 
                    OT7HeaderToMatch,
                        // The HeaderKey value of an OT7 record header. 
                        // This is an 8-byte hash.
                        //
                    ParsedKeyID, 
                        // KeyID identifies a key definition by number.  
                        //
                    DefaultPassword,
                        // Password to use when computing the hash.
                        //
                    (u8*) &KeyIDHash128bit[0] );
                        // OUT: Output buffer for the 128-bit hash produced 
                        //      by this function.
                        
                // If the KeyIDHash fields match, then go return the found
                // information.
                if( IsMatchingBytes( 
                        (u8*) &OT7HeaderToMatch[KEYIDHASH_FIELD_OFFSET],
                        (u8*) &KeyIDHash128bit[0],
                        KEYIDHASH_FIELD_SIZE ) )
                {
                    // Make a return copy of the default password string.
                    PasswordToReturn = 
                        DuplicateString( DefaultPassword );
                            
                    goto ReturnFoundInfo;
                }
                else // No match, so try the next definition.
                {
                    goto TryNextDefinition;
                }
                
            } // if( ParseResult == RESULT_OK )
            
        } // if( S )
        
////////////////////
TryNextDefinition://
////////////////////
  
        // Advance the item cursor to the next string in the key map list.
        ToNextItem(&C);
    }
    
    // No match was found by this point.
    
    // Return 0 for the key definition to mean that there was no match.
    *KeyDefinition = 0;
     
    // Go clean up the working buffers.
    goto CleanUp;
     
    //--------------------------------------------------------------------------
    
//////////////////    
ReturnFoundInfo://
////////////////// 

    // Decode the KeyAddress field.
    
    // XOR the KeyAddress with the hash value in the KeyAddress field.
    XorBytes( (u8*) &OT7HeaderToMatch[KEYADDRESS_FIELD_OFFSET], // From 
              (u8*) &KeyIDHash128bit[KEYIDHASH_FIELD_SIZE],     // To  
              KEYADDRESS_FIELD_SIZE );                          // ByteCount
    
    // Return the decoded KeyAddress.          
    *KeyAddress = 
        Get_u64_LSB_to_MSB( (u8*) &KeyIDHash128bit[KEYIDHASH_FIELD_SIZE] );

    // Return the KeyID found.
    *FoundKeyID = ParsedKeyID;
    
    // Return a copy of the password found to decrypt the header. This will 
    // need to be deallocated later.
    *FoundPassword = PasswordToReturn;
    
    // Return the location of the key definition in the key map list, the Item 
    // address of the first string of the key definition.
    *KeyDefinition = C.TheItem;
    
//////////    
CleanUp://
//////////  
  
    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential 
    // for information leakage.
    //--------------------------------------------------------------------------
    
    // Zero the local variables.
    KeyPassword = 0;
    ParsedKeyID = 0;
    ParseResult = 0;
    PasswordToReturn = 0;
    S = 0;
    
    // Zero the Item cursor record.
    ZeroBytes( (u8*) &C, sizeof(ThatItem) );
    
    // Zero the KeyIDHash128bit buffer.
    ZeroBytes( (u8*) &KeyIDHash128bit[0], KEYIDHASH128BIT_BYTE_COUNT );
     
    // Zero all of the stack locations used to pass parameters into this
    // routine.
    KeyMapList = 0;
    PasswordForSearching = 0;
    OT7HeaderToMatch = 0;
    FoundKeyID = 0;
    FoundPassword = 0;
    KeyAddress = 0;
    KeyDefinition = 0;
}

/*------------------------------------------------------------------------------
| LookupOffsetOfFirstUnusedKeyByte
|-------------------------------------------------------------------------------
|
| PURPOSE: To get the file offset of the first unused key byte in a one-time
|          pad key file.
|
| DESCRIPTION: A log file is maintained to keep track of how many key bytes 
| have been used in one-time pad key files. This file is named 'ot7.log' by 
| default, but a different name can also be specified on the command line. 
|
| Each line of the log file consists of an identifier for a key file followed 
| by a space and then a decimal number representing the offset in the file 
| of the first unused key byte. For example, here is a line from the log file:
|
|            2819ED98F3020672 24875
|                   /            \
|     FileID Hash__/              \___Offset of first unused key byte
|
| The first 32 bytes of each one-time pad key file is reserved as the 
| signature of the file and not used for encryption. An 8-byte FileID hash 
| is computed from this 32-byte signature, and it is that value which is stored
| in the 'ot7.log' file.
|
| This routine may create a linked list of strings when reading the log file.
| Some other routine will need to deallocate the log file string list.
|
| HISTORY: 
|    28Dec13 
|    23Feb14 Fixed reading of list of text lines to LogFileList parameter: was
|            assigning zero to LogFileList.Value instead of the address of a
|            List record.
------------------------------------------------------------------------------*/
    // OUT: Offset of the first unused key byte in the file.
u64 //
LookupOffsetOfFirstUnusedKeyByte( s8* KeyHashString )
                                        // A hash string that identifies a 
                                        // one-time pad key file.
 {
    s8* S;
    s8* End;
    u32 ByteCount;
    List* L;
    ThatItem C;
    u64 OffsetOfFirstUnusedByte;
    
    // If the log file hasn't been loaded into memory yet, then read it from the 
    // log file as a linked list of strings, one per line.  
    if( LogFileList.IsSpecified == 0 )
    {
        // Try to read the log file into a string list.
        L = ReadListOfTextLines( LogFileName.Value );
        
        // If able to read the contents of the log file, then assign the list
        // to the LogFileList parameter.
        if( L )
        {
            // Print a status message if in verbose mode.
            if( IsVerbose.Value )
            {
                printf( "Read log file '%s' with %d items.\n", 
                        LogFileName.Value,
                        L->ItemCount );
            }
            
            // If the LogFileList has a default value, then delete it.
            if( LogFileList.Value )
            {
                DeleteListOfDynamicData( LogFileList.Value );
            }
            
            // Assign the list just read to the LogFileList parameter.
            LogFileList.Value = L;
            
            // Mark the LogFileList parameter as having been specified.
            LogFileList.IsSpecified = 1;
        }
    }

    // If no log file could not be read, then no key bytes have been used in 
    // any key file.
    if( LogFileList.IsSpecified == 0 )
    {
        // Print a status message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "Could not read log file '%s' into memory: \n", 
                    LogFileName.Value );
                    
            printf( "this is normal if no file has ever been encrypted.\n" );
        }

        // Return the first available byte for crypto use, the one following
        // the file signature.
        OffsetOfFirstUnusedByte = (u64) KEY_FILE_SIGNATURE_SIZE;
        
        // Go to the common exit for this routine.
        goto Finish;
    }
       
    // Refer to the first item in the list using cursor C.
    ToFirstItem( LogFileList.Value, &C ); 
    
    // Scan the list to the end or until a match is found.
    while( C.TheItem )    
    {
        // Scan the current text line for the hash string.
        // Returns the address of the hash in the string, or 0 if not found.
        S = FindStringInString( 
                KeyHashString, 
                (s8*) C.TheItem->DataAddress );
    
        // If the hash was found, then parse the integer following the hash.
        if( S )
        {
            // Print a status message if in verbose mode.
            if( IsVerbose.Value )
            {
                printf( "Found entry for key file in log file: [%s].\n", 
                        (s8*) C.TheItem->DataAddress );
            }

            // This is the situation:
            //
            //     S
            //     |
            //     v
            //     2819ED98F3020672 24875
        
            // Get the number of bytes in the string.
            ByteCount = CountString( (s8*) C.TheItem->DataAddress );    
            
            // Calculate the address of the first byte after the string,
            // at the zero-terminator if the string has one.
            End = (s8*) C.TheItem->DataAddress + ByteCount;
            
            // Advance S to the byte following the hash.
            S += KEY_FILE_HASH_SIZE*2;
            
            //                     S
            //                     |
            //                     v
            //     2819ED98F3020672 24875
            
            // Parse the number representing the offset of the first unused key
            // byte.
            //
            // OUT: The value parsed from the string. The cursor S is advanced. 
            //      
            OffsetOfFirstUnusedByte =
                ParseUnsignedInteger(  
                    &S,   // IN/OUT: Address of the address of the current 
                          //         character.
                          //
                    End );// Address of the first byte after the buffer, a 
                          // limit on how far forward scanning can go.
            
            // Go return the value found.
            goto Finish;
        }
        
        // Advance the item cursor to the next item in the list.           
        ToNextItem(&C);
    }
    
    // The hash was not found, so that means no bytes in the key file have been
    // used.
    
    // Return the first available byte for crypto use, the one following
    // the file signature.
    OffsetOfFirstUnusedByte = (u64) KEY_FILE_SIGNATURE_SIZE;

/////////
Finish://
/////////

    // Print a status message if in verbose mode.
    if( IsVerbose.Value )
    {
        printf( "The first unused byte in the key file is at address %s.\n", 
                ConvertIntegerToString64(OffsetOfFirstUnusedByte) );
    }
     
    // Return the byte offset of the first unused byte in the one-time pad
    // key file.
    return( OffsetOfFirstUnusedByte );
    
    // Some other routine will need to deallocate the log file string list.
}
 
/*------------------------------------------------------------------------------
| MakeItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To make a new empty, non-inserted Item record.
|
| DESCRIPTION: 
|
| HISTORY: 
|    17Nov13 Revised to use calloc().
------------------------------------------------------------------------------*/
        // OUT: Address of a new Item record, or 0 if unable to allocate an Item
Item*   //      record.
MakeItem()
{
    Item* I;

    // Allocate a new item control block, filling the record with zeros.
    I = (Item*) calloc( 1, sizeof(Item) );
     
    // If the record was allocated, update the tracking counter for items in
    // use.
    if( I )
    {
        CountOfItemsInUse++;
    }
       
    // Return the item.
    return( I );        
}

/*------------------------------------------------------------------------------
| MakeItemForData
|-------------------------------------------------------------------------------
|
| PURPOSE: To make a new Item and associate it with the given data.
|
| DESCRIPTION: Makes a generic item record capable of pointing to data of any 
| kind, at any address in memory. 
|
| The data at the SomeData address is not modified by this routine. 
|
| EXAMPLE:       AnItem = MakeItemForData( "This is some data." );
|
| HISTORY: 
|    07Oct91
|    29Oct93 Ported from Focus. 
|    10Dec96 Added setting of the buffer address as well as the data address.
|    17Nov13 Revised to handle allocation failure case.
|    28Feb14 Removed unused BufferAddress from Item record and setting in this
|            routine.
------------------------------------------------------------------------------*/
        // OUT: Address of a new Item record that refers to the given data, or
        //      0 if unable to allocate a new Item record.
Item*   //
MakeItemForData( u8* SomeData )
{
    Item* ThisItem;
    
    // Make a new Item record, or return 0 if allocation failed. 
    ThisItem = MakeItem();
    
    // If the Item record was allocated, then associate it with the given data.
    if( ThisItem )
    {
        // Associate the Item with the data using the DataAddress field.
        ThisItem->DataAddress = SomeData;
    }
    
    // Return the address of the new Item record, or 0 if unable to allocate a 
    // new Item record.
    return( ThisItem );
}

/*------------------------------------------------------------------------------
| MakeList
|-------------------------------------------------------------------------------
|
| PURPOSE: To make a new empty, unmarked list.
|
| DESCRIPTION: This routine allocates a new linked list control block from the
| general memory pool.
|
| If a valid list record is allocated, then it is ready to add items to the 
| list.
|
| Use DeleteList() to deallocate the record produced using this routine.
|
| EXAMPLE:  L = MakeList();
|
| HISTORY: 
|    17Nov13 Revised to use calloc().
------------------------------------------------------------------------------*/
        // OUT: An empty list or zero if a list could not be allocated.
List*   //      
MakeList()
{
    List* L;

    // Allocate a new list control block, filling the record with zeros.
    L = (List*) calloc( 1, sizeof(List) );
    
    // If the block was not allocated.
    if( L == 0 )
    {
        // Fail by returning zero.
        return(0);
    }
    
    // Account for the new list now in use.
    CountOfListsInUse++;
        
    // Return the list.
    return( L );        
}

/*------------------------------------------------------------------------------
| MarkItemAsFirst
|-------------------------------------------------------------------------------
|
| PURPOSE: To mark an item as first in a list.
|
| DESCRIPTION: Zero is used at both ends of the list to mark the ends.
|
| HISTORY: 
|    09Jan88
|    10Jul89 new structure revision
------------------------------------------------------------------------------*/
void
MarkItemAsFirst(Item* AnItem)
{
    // Put 0 in the link to the prior item to mark the item as first.
    AnItem->PriorItem = 0;
}

/*------------------------------------------------------------------------------
| MarkItemAsLast
|-------------------------------------------------------------------------------
|
| PURPOSE: To mark an item as last in a list.
|
| DESCRIPTION: Zero is used at both ends of the list to mark the ends.
|
| EXAMPLE:                   MarkItemAsLast(AnItem);
|
| HISTORY: 
|    09Jan88
|    10Jul89 New structure revision.
------------------------------------------------------------------------------*/
void
MarkItemAsLast( Item* AnItem )
{
    // Put 0 in the link to the next item to mark the item as last.
    AnItem->NextItem = 0;
}

/*------------------------------------------------------------------------------
| LoadFileToBuffer
|-------------------------------------------------------------------------------
|
| PURPOSE: To mark a list as having no items.
|
| DESCRIPTION: This routine sets fields in a List record to mark it as not 
| having items.
|
| HISTORY: 
|    04Jan89
------------------------------------------------------------------------------*/
void
MarkListAsEmpty( List* L )
{
    // Zero the item counter.
    L->ItemCount = 0;
    
    // Zero the address of the first item in the list to mark it as invalid.
    L->FirstItem = 0;
    
    // Zero the address of the last item in the list to mark it as invalid.
    L->LastItem  = 0;
}

/*------------------------------------------------------------------------------
| NumberOfSignificantBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To measure how many bytes are required to represent a non-zero
|          integer.
|
| DESCRIPTION: Given an unsigned 64-bit integer, this routine figures out how 
| many bytes are required to represent the value if it is non-zero. This is the 
| number of bytes after taking away leading zero bytes from the most-sigificant
| end of the number.
|
| HISTORY: 
|    07Feb14 
|    27Feb14 Fixed bug in while loop test resulting in 8 being returned by this 
|            routine even for small values of Number.
------------------------------------------------------------------------------*/
    // OUT: How many bytes are required to represent the number, a value from 
    //      0 to 8.
u8  //
NumberOfSignificantBytes( u64 Number )
{
    u8  n;
    u64 Mask;
    
    // Start with 8 bytes required to begin with.
    n = 8;
    
    // Initialize the mask to refer to the most-significant byte.
    Mask = 0xFF00000000000000LL;
    
    // While bytes remain to be tested and the masked part of the number is 
    // zero, then decrement the number of bytes required by one.
    while( n && ((Mask & Number) == 0) )
    {
        // Reduce the number of bytes required by one.
        n--;
        
        // Shift the mask over by 8 bits.
        Mask >>= 8;
    }
    
    // Return the number of bytes required.
    return( n );
}

/*------------------------------------------------------------------------------
| OpenFileX
|-------------------------------------------------------------------------------
| 
| PURPOSE: To open a file to access base64 or binary data.
|
| DESCRIPTION: The format of an OT7 encrypted file can be either binary or
| base64. To make it more convenient to access either type of file, the state 
| info required for base64 encoding is combined with a file handle.
|
| There are a set of file I/O routines that use FILEX handles in place of the 
| standard FILE handle.
|
| HISTORY: 
|    17Oct13 
|    25Feb14 Added printing of status and error messages, and setting of global
|            result code in the event of an error.
|    16Mar14 Revised to take address of extended file control block as an input
|            rather than using a single global record. Now returns status code
|            rather than file control block address.
------------------------------------------------------------------------------*/
        // OUT: Status code of 1 if opened OK, or zero if there was an error.
int     //
OpenFileX( 
    FILEX* F,
            // Extended file handle record to be used.
            //
    s8* FileName, 
            // Name of the file to be opened, a zero-terminated string.
            // 
    s8  EncryptedFileFormat,
            // How the file is encoded, either binary or base64.
            // Use these codes here : OT7_FILE_FORMAT_BINARY or 
            //                        OT7_FILE_FORMAT_BASE64
    s8* AccessMode ) 
            // How the file will be accessed, a standard fopen64 parameter, 
            // either "wb" or "rb". The file is processed linearly from start
            // to finish, and only written or read, but not both.
{
    s8* AccessModeString;
    s8* FileFormatString;
    u32 ResultCodeIfError;
    
    // Select a name string for the file format given a file format code.
    switch( EncryptedFileFormat )
    {
        case OT7_FILE_FORMAT_BASE64:
        {
            FileFormatString = "base64";
            break;
        }
        
        case OT7_FILE_FORMAT_BINARY:
        {
            FileFormatString = "binary";
            break;
        }
    }
    
    // Pick a descriptive string for the file access mode and also the
    // error code to be used in the event of an error.
    switch( AccessMode[0] )
    {
        case 'r': // 'rb'
        {
            AccessModeString = "reading";
            
            ResultCodeIfError = RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING;
            
            break;
        }
    
        case 'w': // 'wb'
        {
            AccessModeString = "writing";
            
            ResultCodeIfError = RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_WRITING;
            
            break;
        }
    }
 
    // Open the file using the standard file open command and save the file
    // handle in the extra file state record.
    F->FileHandle = fopen64( FileName, AccessMode );
    
    // If file was opened OK, print a status message in verbose mode.
    if( F->FileHandle )
    {
        // Print status message if in verbose mode. 
        if( IsVerbose.Value )
        {
            printf( "Opened encrypted file '%s' for %s %s data.\n", 
                     FileName,
                     AccessModeString,
                     FileFormatString );
        }
    }
    else // Unable to open the file, so print an error message and set 
         // the global result code to indicate the error.
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't open encrypted file '%s' for %s %s data.\n", 
                     FileName,
                     AccessModeString,
                     FileFormatString );
        }
        
        // Set the global result code based on the type of error that
        // occurred.
        Result = ResultCodeIfError;
        
        // Return 0 to mean an error occurred.
        return(0);
    }
    
    // At this point the file is open.

    // Save the file format information in the file state record.
    F->FileFormat = EncryptedFileFormat;
    
    // Start the file position at 0, the current byte offset from the beginning 
    // of the file.
    F->FilePositionInBytes = 0;
        
    // If the encrypted file format is base64, then initialize the fields used
    // by the format.
    if( EncryptedFileFormat == OT7_FILE_FORMAT_BASE64 )
    {
        // Initialize the current offset from the beginning of the file in terms 
        // of 6-bit words, ignoring whitespace and padding.
        F->FilePositionIn6BitWords = 0;
    }
    
    // Return status code 1 to mean file was opened OK.
    return( 1 );
}

/*------------------------------------------------------------------------------
| OpenKeyFile
|-------------------------------------------------------------------------------
|
| PURPOSE: To open a one-time pad key file.
|
| DESCRIPTION: Opens the file as read-only or for read/write access depending
| on whether or not key bytes will be erased.
|
| HISTORY: 
|    29Dec13 
|    24Feb14 Added printing of status messages on successful file open in 
|            verbose mode.
------------------------------------------------------------------------------*/
      // OUT: File handle, or 0 if an error occurred.
FILE* //
OpenKeyFile( s8* KeyFileName )
                     // Name of the one-time pad file, a zero-terminated string.
{
    FILE* KeyFileHandle;

    // If key bytes will be erased, then open the file for read/write access.
    if( IsEraseUsedKeyBytes.Value )
    {
        // Open the one-time pad file for reading and writing binary data.
        KeyFileHandle = fopen64( KeyFileName, "r+b" );

        // If file was opened OK, print a status message in verbose mode.
        if( KeyFileHandle )
        {
            // Print status message if in verbose mode. 
            if( IsVerbose.Value )
            {
                printf( "Opened key file '%s' for reading and writing.\n", 
                         KeyFileName );
            }
        }
        else // Unable to open the key file, so print an error message and set 
             // the global result code to indicate the error.
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( 
                    "ERROR: Can't open key file '%s' for reading and writing.\n", 
                    KeyFileName );
            }

            // Set the result code to be returned when the application exits.
            Result = RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING;
        }
    }
    else // Not erasing used key bytes.
    {
        // Open the one-time pad key file for reading binary data.
        KeyFileHandle = fopen64( KeyFileName, "rb" );

        // If file was opened OK, print a status message in verbose mode.
        if( KeyFileHandle )
        {
            // Print status message if in verbose mode. 
            if( IsVerbose.Value )
            {
                printf( "Opened key file '%s' for reading.\n", KeyFileName );
            }
        }
        else // Unable to open the key file, so print an error message and set 
             // the global result code to indicate the error.
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't open key file '%s' for reading.\n", 
                        KeyFileName );
            }

            // Set the result code to be returned when the application exits.
            Result = RESULT_CANT_OPEN_KEY_FILE_FOR_READING;
        }
    }
 
    // Return the file handle, or 0 if unable to open.
    return( KeyFileHandle );
}

/*------------------------------------------------------------------------------
| ParseCommandLine
|-------------------------------------------------------------------------------
|
| PURPOSE: To parse OT7 command line parameters to set global variables.
|
| DESCRIPTION: This routine converts user instructions into a form that can be
| executed by the other parts of this application.
|
| HISTORY: 
|    19Oct13 
|    05Jan14 Added parsing of -ID parameter.
|    02Feb14 Added parsing of the -keymask parameter.
|    08Feb14 Added parsing of the -nofilename parameter.
|    09Feb14 Added parsing of the -KeyID parameter. Reordered parameters to be
|            roughly in alphabetical order with a few exceptions to avoid
|            collisions between short and long parameters with the same prefix.
|    17Feb14 Replace -o tags with -od and -oe, to make separate output file
|            name parameters for encryption and decryption.
|    21Feb14 Added support for default plaintext file name 'plain.txt'.
|    22Feb14 Factored out ParseFileNameParameter() and 
|            ParseWordOrQuotedPhrase().
|    26Feb14 Revised '-unused' to also support shorter '-u' tag. Added '-p'.
|            Added skipping of file names in already-defined parameters.
|    01Mar14 Move printing of the application banner to this routine so that
|            status messages during parsing will be printed after the 
|            application name and version number.
|    29Mar14 Moved test for no parameters to following printing of the 
|            application banner. Fixed parsing of multi-word phrases contained
|            in quotes. Revised to use ParseWordsOrQuotedPhrase() instead of
|            ParseWordOrQuotedPhrase() which was clipping multi-word phrases
|            at the first space.
|    30Nov14 Added '-testhash' option for hash function test routine.
------------------------------------------------------------------------------*/
    // OUT: Result code to be passed back to the calling application, one of the
    //      values with the prefix 'RESULT_...'.
int //
ParseCommandLine( 
    s16 argc,
            // Number of whitespace delimited words on the command line, 
            // including the name of the application.
            // 
    s8** argv )
            // An array of strings formed from the command line.
{
    u32 v;
    s16 i;
    static u8 IsAppNamePrinted = 0;
    s8* S;
    u32 result;
    static ParameterValueString[MAX_PARAMETER_VALUE_SIZE];
    
    // Set the default result code to be no error.
    result = RESULT_OK;
   
    // Scan the parameters following the program name to see if verbose mode
    // should be enabled/disabled before interpreting the other parameters.
    for( i = 1; i < argc; i++ ) 
    {
        // If the '-v' parameter is found and the verbose mode parameter has 
        // not yet been set, then enable verbose mode.
        if( IsPrefixForString( "-v", argv[i] ) && 
            (IsVerbose.IsSpecified == 0) )
        {
            // If verbose mode is not yet enabled, then enable it.
            if( IsVerbose.Value == 0 )
            {
                // Set a status flag to mean that status messages should
                // be printed.
                IsVerbose.Value = 1;
                
                // Print status when verbose mode is enabled.
                printf( "Verbose mode is enabled.\n" );
            }

            // Mark the IsVerbose parameter has having been specified.
            IsVerbose.IsSpecified = 1;
        }
        
        // If the '-silent' parameter is found and the verbose mode parameter 
        // has not yet been set, then disable verbose mode.
        if( IsPrefixForString( "-silent", argv[i] ) && 
            (IsVerbose.IsSpecified == 0) )
        {
            // Clear the status flag to mean that status messages should
            // not be printed.
            IsVerbose.Value = 0;
            
            // Mark the IsVerbose parameter has having been specified.
            IsVerbose.IsSpecified = 1;
        }
    }
    
    // Print application name and version one time if verbose mode is enabled.
    if( IsVerbose.Value && (IsAppNamePrinted == 0) )
    {
         // Print the application identifier and version number.
        printf( "%s\n", OT7_VERSION_STRING );
         
        // Print a dividing line to group status messages that follow.
        printf( "--------------------------------------------------------------"
                "------------------\n" );
         
        // Set a flag to suppress printing of the application banner if this
        // routine is called again to parse the parameters of a key definition
        // found in the key map.
        IsAppNamePrinted = 1;
    }
    
    //--------------------------------------------------------------------------
    
    // If no command line parameters are given, return the result code for that.
    if( argc < 2 )
    {
        // Return the result code meaning that no command line parameters were
        // given.
        result = RESULT_NO_COMMAND_LINE_PARAMETERS_GIVEN;
        
        // Go clean up and exit from this routine.
        goto CleanUp;
    }
     
    //--------------------------------------------------------------------------
     
    // For each of the parameters following the program name, interpret them one
    // by one to set global variables.
    for( i = 1; i < argc; i++ ) 
    {
         // If the '-base64' parameter is found and the EncryptedFileFormat 
        // parameter has not yet been set, then set it. This is the default
        // encoding format, so this parameter is optional.
        //
        // -base64   Set the output format to be base64-encoded data.
        if( IsPrefixForString( "-base64", argv[i] ) && 
            (EncryptedFileFormat.IsSpecified == 0) )
        {
            // Set the encrypted file format to base64.
            EncryptedFileFormat.Value = OT7_FILE_FORMAT_BASE64;
            
            // Mark the encrypted file format parameter has having been 
            // specified.
            EncryptedFileFormat.IsSpecified = 1;
              
            // All done with the -base64 parameter.
            continue;
        }
        
        //----------------------------------------------------------------------
        // If the '-binary' parameter is found and the EncryptedFileFormat 
        // parameter has not yet been set, then set it.
        //
        // -binary   Set the output format to be binary data.
        if( IsPrefixForString( "-binary", argv[i] ) && 
            (EncryptedFileFormat.IsSpecified == 0) )
        {
            // Set the encrypted file format to binary.
            EncryptedFileFormat.Value = OT7_FILE_FORMAT_BINARY;
            
            // Mark the encrypted file format parameter has having been 
            // specified.
            EncryptedFileFormat.IsSpecified = 1;
              
            // All done with the -binary parameter.
            continue;
        }
        
        //----------------------------------------------------------------------
                  
        // If the '-d' parameter is found, then parse any file name that 
        // follows.
        //
        // -d [<file name>]  Decrypt a file.
        if( IsPrefixForString( "-d", argv[i] ) )
        {
            // Set a status flag to mean that decryption should be done. 
            IsDecrypting.Value = 1;
        
            // Mark the IsDecrypting parameter has having been specified.
            IsDecrypting.IsSpecified = 1;
                     
            // If another string follows -d, then interpret that as the name of 
            // the file to be decrypted.
            if( (i+1) < argc )
            {
                // Parse the file name from a string and assign it to a file
                // name.
                result = 
                    ParseFileNameParameter( 
                        &NameOfEncryptedInputFile,
                            // Address of a string parameter that holds a file 
                            // name.
                            // 
                        argv[i+1] );
                            // String holding the file name to be parsed and 
                            // assigned to the given file name parameter if it 
                            // is unspecified.
                 
                // If there was an error parsing the file name, then exit with
                // an error code.
                if( result != RESULT_OK )
                {
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file name in 
                // the parameter list.
                i++;            
            }
            
            // If the '-d' tag is last on the command line, then the default
            // name of the encrypted input file name will be used for
            // decryption.
                      
            // All done with the -d [<filename>] parameters.
            continue;
        }
        
        //----------------------------------------------------------------------

        // If the '-erasekey' parameter is found and the IsEraseUsedKeyBytes 
        // parameter has not yet been set, then set it.
        //
        // -erasekey   Print the the number of available key bytes. 
        if( IsPrefixForString( "-erasekey", argv[i] ) && 
            (IsEraseUsedKeyBytes.IsSpecified == 0) )
        {
            // Set a status flag to mean that used key bytes should be erased.
            IsEraseUsedKeyBytes.Value = 1;    
            
            // Mark the erase used key bytes parameter has having been 
            // specified.
            IsEraseUsedKeyBytes.IsSpecified = 1;
             
            // All done with the -erasekey parameter.
            continue;
        }
                
        //----------------------------------------------------------------------

        // If the '-e' parameter is found, then enable encryption. In this 
        // routine, parsing the '-e' option needs to follow '-erasekey' parsing 
        // to avoid confusion.
        //
        // -e <file name>  Encrypt a file.
        if( IsPrefixForString( "-e", argv[i] ) )
        {
            // Set a status flag to mean that encryption should be done. 
            IsEncrypting.Value = 1;
        
            // Mark the IsEncrypting parameter has having been specified.
            IsEncrypting.IsSpecified = 1;
            
            // If another string follows -e, then interpret that as the name 
            // of the file to be encrypted.
            if( (i+1) < argc )
            {
                // Parse the file name from a string and assign it to a file
                // name.
                result = 
                    ParseFileNameParameter( 
                        &NameOfPlaintextFile,
                            // Address of a string parameter that holds a file 
                            // name.
                            // 
                        argv[i+1] );
                            // String holding the file name to be parsed and 
                            // assigned to the given file name parameter if it 
                            // is unspecified.
                 
                // If there was an error parsing the file name, then exit with
                // an error code.
                if( result != RESULT_OK )
                {
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file name in 
                // the parameter list.
                i++;            
            } 
                
            // If the '-e' tag is last on the command line, then the default
            // name of the plaintext input file name will be used for
            // encryption.
                       
            // All done with the -e [<filename>] parameters.
            continue;
        }
        
        //----------------------------------------------------------------------
        // If the number of fill bytes has given and has not yet been specified,
        // then set it to the value following -f.
        //
        // -f <# of fill bytes>, eg. -f 1024  
        if( IsPrefixForString( "-f", argv[i] ) )
        {        
            // If no parameter follows '-f' on the command line, then
            // stop scanning and return an error as the result code.
            if( i+1 == argc )
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '%s'.\n", argv[i] );
                }
                
                // Return error code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
                    
            // If the fill size hasn't be specified yet, then set it.
            if( FillSize.IsSpecified == 0 )
            {
                // Use 'S' as a string cursor for parsing the integer from
                // the parameter that follows '-f'.
                S = argv[i+1];
                
                // Parse the integer from the next parameter string.
                FillSize.Value = ParseUnsignedInteger( &S, S + CountString(S) );
                
                // Set a status flag to mean that the number of fill bytes
                // has been specified on the command line.
                FillSize.IsSpecified = 1;
            }
            
            // Add 1 to i to skip over the string with the integer.
            i++;
            
            // All done with this parameter.
            continue;
        }
        
        //----------------------------------------------------------------------
        // If help or usage info should be printed, then set a flag to print
        // usage info.
        //
        // Treat all parameters that start with '-h' as requests for usage info.
        // -h    Print usage info.
        // -help Print usage info.
        if( IsPrefixForString( "-h", argv[i] ) )
        {        
            // Set a status flag to mean that usage info should be printed to 
            // standard output.
            IsHelpRequested.Value = 1;
                       
            // Set a status flag to mean that help info has been requested on
            // the command line.
            IsHelpRequested.IsSpecified = 1;
               
            // All done with this parameter.
            continue;
        }
        
        //----------------------------------------------------------------------

        // If the '-ID' parameter is found, then add it to the list of ID
        // strings. Allow multiple ID strings to be specified, accumulating 
        // them in a list.
        //
        // -ID <identifier>  Specify a key definition identifier.
        if( IsPrefixForString( "-ID", argv[i] ) )
        {
            // If another string follows -ID, then interpret that as the name of 
            // an identifier associated with a key definition in a 'key.map' 
            // file.
            if( (i+1) < argc )
            {
                // Refer to the identifier with the parsing cursor 'S'.
                S = argv[i+1];
                
                // Parse the next word(s) or quoted phrase from a string, 
                // removing any quotes. Use 'v' to count the number of bytes 
                // in the value string parsed from the text line. 
                v = ParseWordsOrQuotedPhrase( 
                        &S,   // IN/OUT: Address of the address of the current 
                              //         character in the string being parsed.
                              //
                        (s8*) &ParameterValueString[0],
                              // Address of the output buffer where the word or 
                              // phrase should be placed.
                              //
                        MAX_PARAMETER_VALUE_SIZE );
                              // Size of the output buffer in bytes.
                
                // If the identifier word or phrase was parsed, then append it
                // to the list of identifiers.
                if( v )
                {
                    // Append the next paramter to the list of identifiers.
                    InsertDataLastInList( 
                        IDStrings.Value, 
                        (u8*) DuplicateString( 
                                (s8*) &ParameterValueString[0] ) );    
                
                    // Mark the IDStrings parameter has having been specified.
                    IDStrings.IsSpecified = 1;
                }
                
                // Increment i to account for having scanned the identifier
                // string in the parameter list.
                i++;            
            }
            else // Return an error code if the identifier is missing.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '-ID'.\n" );
                }
 
                // Return the result code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
            
            // All done with the -ID <identifier> parameters.
            continue;
        }
        
        //----------------------------------------------------------------------

        // If the '-keyfile' parameter is found, then add it to the list of key
        // files. Allow multiple files to be specified, accumulating them in a
        // list.
        //
        // -keyfile <file name>  Specify the key file name. 
        if( IsPrefixForString( "-keyfile", argv[i] ) )
        {
            // If another string follows -keyfile, then interpret that as the
            // name of the file containing random key data for encryption or 
            // decryption.
            if( (i+1) < argc )
            {
                // If the file name is invalid, then exit with an error.
                if( IsFileNameValid( argv[i+1] ) == 0 )
                {
                    // Print an error message if in verbose mode.
                    if( IsVerbose.Value )
                    {
                        printf( "ERROR: Invalid key file name.\n" );
                    }
                
                    // Return error code for an invalid key file name.
                    result = RESULT_INVALID_KEY_FILE_NAME;
                    
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }

                // Refer to the file name with the parsing cursor 'S'.
                S = argv[i+1];
                
                // Parse the next word(s) or quoted phrase from a string, 
                // removing any quotes. Use 'v' to count the number of bytes in 
                // the value string parsed from the text line. 
                v = ParseWordsOrQuotedPhrase( 
                        &S,   // IN/OUT: Address of the address of the current 
                              //         character in the string being parsed.
                              //
                        (s8*) &ParameterValueString[0],
                              // Address of the output buffer where the word or 
                              // phrase should be placed.
                              //
                        MAX_PARAMETER_VALUE_SIZE );
                              // Size of the output buffer in bytes.
                
                // If the file name was parsed, then append it to the list of
                // key files.
                if( v )
                {
                    // Use the next parameter as the name of the one-time pad 
                    // key file. Append the file name to list of key files.
                    InsertDataLastInList( 
                        KeyFileNames.Value, 
                        (u8*) DuplicateString( 
                                (s8*) &ParameterValueString[0] ) );    
                    
                    // Mark the key filename parameter has having been 
                    // specified.
                    KeyFileNames.IsSpecified = 1;
                }
                else // Missing file name parameter.
                {
                    // Print an error message if in verbose mode.
                    if( IsVerbose.Value )
                    {
                        printf( 
                            "ERROR: Missing parameter after '-keyfile'.\n" );
                    }
                    
                    // Return error code for a missing command line parameter.
                    result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                    
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file
                // name in the parameter list.
                i++;            
            }
            else // Return an error code if the file name is missing.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '-keyfile'.\n" );
                }
                
                // Return error code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
            
            // All done with the -keyfile <filename> parameters.
            continue;
        }
                                                  
        //----------------------------------------------------------------------
        // -KeyID is the KeyID value for the OT7 record header, a 64-bit 
        // integer. For decryption, specifying a KeyID causes the KeyID in the 
        // OT7 record header to be ignored, and the specified KeyID is used 
        // instead for locating the decryption key file. This integer may be in 
        // decimal or hex format. 
        //
        // -KeyID <64-bit integer>, eg. -KeyID 0x1923ed484030fe0c
        if( IsPrefixForString( "-KeyID", argv[i] ) )
        {        
            // If no parameter follows '-KeyID' on the command line, then
            // stop scanning and return an error as the result code.
            if( i+1 == argc )
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( 
                        "ERROR: Missing parameter after '%s'.\n", argv[i] );
                }
                
                // Return error code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
           
            // If the KeyID hasn't been specified, then parse the number that
            // follows '-KeyID'.
            if( KeyID.IsSpecified == 0 ) 
            {
                // Use 'S' as a string cursor for parsing the integer from
                // the parameter that follows '-KeyID'.
                S = argv[i+1];
                
                // Parse the integer from the next parameter string.
                KeyID.Value = ParseUnsignedInteger( &S, S + CountString(S) );
                
                // Set a status flag to mean that the key mask has been 
                // specified.
                KeyID.IsSpecified = 1;
            }
            
            // Add 1 to i to skip over the string with the integer.
            i++;
            
            // All done with this parameter.
            continue;
        }
                
        //----------------------------------------------------------------------

        // If the '-keymap' parameter is found, then set it.
        //
        // -keymap <file name>  Specify the key map file name. 
        if( IsPrefixForString( "-keymap", argv[i] ) )
        {
            // If another string follows -keymap, then interpret that as the
            // name of the key map file used to provide key definitions for
            // encryption or decryption.
            if( (i+1) < argc )
            {
                // Parse the file name from a string and assign it to a file
                // name.
                result = 
                    ParseFileNameParameter( 
                        &KeyMapFileName,
                            // Address of a string parameter that holds a file 
                            // name.
                            // 
                        argv[i+1] );
                            // String holding the file name to be parsed and 
                            // assigned to the given file name parameter if it 
                            // is unspecified.
                 
                // If there was an error parsing the file name, then exit with
                // an error code.
                if( result != RESULT_OK )
                {
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file name in 
                // the parameter list.
                i++;            
            }
            else // Missing file name parameter.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( 
                        "ERROR: Missing parameter after '-keymap'.\n" );
                }
                    
                 // Return error code for missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
         
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
             
            // All done with the -keymap <filename> parameters.
            continue;
        }
                 
        //----------------------------------------------------------------------

        // If the '-logfile' parameter is found, then set it.
        //
        // -logfile <file name>  Specify the log file name. 
        if( IsPrefixForString( "-logfile", argv[i] ) )
        {
            // If another string follows -logfile, then interpret that as the
            // name of the log file used to track used key bytes.
            if( (i+1) < argc )
            {
                // Parse the file name from a string and assign it to a file
                // name.
                result = 
                    ParseFileNameParameter( 
                        &LogFileName,
                            // Address of a string parameter that holds a file 
                            // name.
                            // 
                        argv[i+1] );
                            // String holding the file name to be parsed and 
                            // assigned to the given file name parameter if it 
                            // is unspecified.
                 
                // If there was an error parsing the file name, then exit with
                // an error code.
                if( result != RESULT_OK )
                {
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file name in 
                // the parameter list.
                i++;            
            }
            else // Return an error code if the file name is missing.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '-logfile'.\n" );
                }
                
                // Return error code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
        
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
            
            // All done with the -logfile <filename> parameters.
            continue;
        }
                
        //----------------------------------------------------------------------
        
        // If the '-nofilename' parameter is found, then disable filename
        // inclusion in OT7 records during encryption.
        if( IsPrefixForString( "-nofilename", argv[i] ) && 
            (IsNoFileName.IsSpecified == 0) )
        {
            // Set the status flag to mean that the plaintext file name should
            // not be included in the encrypted OT7 file to be produced.
            IsNoFileName.Value = 1;
            
            // Mark the IsVerbose parameter has having been specified.
            IsNoFileName.IsSpecified = 1;
            
            // All done with the -nofilename parameter.
            continue;
        }
         
        //----------------------------------------------------------------------

        // If the '-od' parameter is found, then set it. This overrides any file 
        // embedded in an OT7 record and also the default decrypted output file 
        // name 'ot7d.out'.
        //
        // -od <file name>  Specify the name of the decrypted output file. 
        if( IsPrefixForString( "-od", argv[i] ) )
        {
            // If another string follows -od, then interpret that as the name
            // of the output file produced by decryption.
            if( (i+1) < argc )
            {
                // Parse the file name from a string and assign it to a file
                // name.
                result = 
                    ParseFileNameParameter( 
                        &NameOfDecryptedOutputFile,
                            // Address of a string parameter that holds a file 
                            // name.
                            // 
                        argv[i+1] );
                            // String holding the file name to be parsed and 
                            // assigned to the given file name parameter if it 
                            // is unspecified.
                 
                // If there was an error parsing the file name, then exit with
                // an error code.
                if( result != RESULT_OK )
                {
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file name in 
                // the parameter list.
                i++;            
            }
            else // Return an error code if the file name is missing.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '-od'.\n" );
                }
                
                // Return error code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
            
            // All done with the -od <filename> parameters.
            continue;
        }
        
        //----------------------------------------------------------------------

        // If the '-oe' parameter is found, then set it. This overrides the 
        // default encrypted output file name 'ot7e.out'.
        //
        // -oe <file name>  Specify the name of the encrypted output file. 
        if( IsPrefixForString( "-oe", argv[i] ) )
        {
            // If another string follows -oe, then interpret that as the name
            // of the output file produced by encryption.
            if( (i+1) < argc )
            {
                // Parse the file name from a string and assign it to a file
                // name.
                result = 
                    ParseFileNameParameter( 
                        &NameOfEncryptedOutputFile,
                            // Address of a string parameter that holds a file 
                            // name.
                            // 
                        argv[i+1] );
                            // String holding the file name to be parsed and 
                            // assigned to the given file name parameter if it 
                            // is unspecified.
                 
                // If there was an error parsing the file name, then exit with
                // an error code.
                if( result != RESULT_OK )
                {
                    // Go clean up and exit from this routine.
                    goto CleanUp;
                }
                
                // Increment i to account for having scanned the file name in 
                // the parameter list.
                i++;            
            }
            else // Return an error code if the file name is missing.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '-oe'.\n" );
                }
                
                // Return error code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
            
            // All done with the -oe <filename> parameters.
            continue;
        }
                                
        //----------------------------------------------------------------------
        // If the '-p' parameter is found, then define the password if it is
        // not yet specified.
        //
        // -p <password string> Specify a password.
        //
        if( IsPrefixForString( "-p", argv[i] ) )
        {
            // If another string follows -p, then interpret that as a password.
            if( (i+1) < argc )
            {
                // Refer to the password with the parsing cursor 'S'.
                S = argv[i+1];
                
                // Parse the word(s) or quoted phrase from a string, removing 
                // any quotes. Use 'v' to count the number of bytes in the 
                // value string parsed from the text line. 
                v = ParseWordsOrQuotedPhrase( 
                        &S,   // IN/OUT: Address of the address of the current 
                              //         character in the string being parsed.
                              //
                        (s8*) &ParameterValueString[0],
                              // Address of the output buffer where the word or 
                              // phrase should be placed.
                              //
                        MAX_PARAMETER_VALUE_SIZE );
                              // Size of the output buffer in bytes.
                
                // If the password parsed and no password has been specified, 
                // then use it in place of the default password.
                if( v )
                {
                    // If a password has already been specified, then report
                    // that the prior password overrides this new one.
                    if( Password.IsSpecified )
                    {
                        // Print a status message if in verbose mode.
                        if( IsVerbose.Value )
                        {
                           printf( "Using command line password instead of key "
                                   "definition password.\n" );
                        }
                    }
                    else // No password has been specified yet.
                    {
                        // Delete the default password.
                        DeleteString( Password.Value );
                        
                        // Use the parsed password as the current password.
                        Password.Value = 
                            DuplicateString( (s8*) &ParameterValueString[0] );    
                    
                        // Mark the password parameter has having been specified.
                        Password.IsSpecified = 1;
                        
                        // Print a status message if in verbose mode.
                        if( IsVerbose.Value )
                        {
                            printf( "Using specified password '%s' in place of "
                                    "default password.\n", Password.Value );
                        }
                    }
                }
                
                // Increment i to account for having scanned the password
                // string in the parameter list.
                i++;            
            }
            else // Return an error code if the password is missing.
            {
                // Print an error message if in verbose mode.
                if( IsVerbose.Value )
                {
                    printf( "ERROR: Missing parameter after '-p'.\n" );
                }
 
                // Return the result code for a missing command line parameter.
                result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
                
                // Go clean up and exit from this routine.
                goto CleanUp;
            }
            
            // All done with the -p <password string> parameter.
            continue;
        }
        
        //----------------------------------------------------------------------

        // If the '-testhash' parameter is found, then enable the hash test.
        if( IsPrefixForString( "-testhash", argv[i] ) )
        {
            // Set a flag to cause the hash function test to be run.
            IsTestingHash.Value = 1;    
            
            // Mark the hash function parameter as has having been specified.
            IsTestingHash.IsSpecified = 1;
             
            // All done with the -testhash parameter.
            continue;
        }
                
        //----------------------------------------------------------------------

        // If the '-u' or '-unused' parameter is found and the 
        // IsReportingUnusedKeyBytes parameter has not yet been set, then set 
        // it.
        //
        // -unused or -u  
        //               Print the the number of unused key bytes in a key file
        //               or pool of key files. 
        if( IsPrefixForString( "-u", argv[i] ) && 
            (IsReportingUnusedKeyBytes.IsSpecified == 0) )
        {
            // Set a status flag to mean that the number of available key bytes 
            // in a specified one-time pad file should be printed to standard 
            // output.
            IsReportingUnusedKeyBytes.Value = 1;    
            
            // Mark the key filename parameter has having been specified.
            IsReportingUnusedKeyBytes.IsSpecified = 1;
             
            // All done with the -unused parameter.
            continue;
        }
                
        //----------------------------------------------------------------------
        // -v Enable verbose mode has already been handled in the pre-parsing
        //    step.
        //
        if( IsPrefixForString( "-v", argv[i] ) )
        {        
            // This section of code is needed so that '-v' won't be treated as 
            // an invalid parameter by the default case.
                
            // All done with this parameter.
            continue;
        }
        
        //----------------------------------------------------------------------
        // -silent Disable verbose mode has already been handled in the 
        //         pre-parsing step.
        //
        if( IsPrefixForString( "-silent", argv[i] ) )
        {        
            // This section of code is needed so that '-silent' won't be 
            // treated as an invalid parameter by the default case.
                
            // All done with this parameter.
            continue;
        }
                 
        //----------------------------------------------------------------------
        // DEFAULT - Any other parameters are invalid.
        //----------------------------------------------------------------------
                 
        // Print an error message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Invalid parameter '%s'.\n", argv[i] );
        }
        
        // Return error code for an invalid command line parameter.
        result = RESULT_INVALID_COMMAND_LINE_PARAMETER;
        
        // Go clean up and exit from this routine.
        goto CleanUp;
        
    } // for( i = 1; i < argc; i++ ) 
 
//////////
CleanUp://
//////////

    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential
    // for information leakage.
    //--------------------------------------------------------------------------

    // Zero local variables except for 'result'.
    v = 0;
    i = 0;
    S = 0;
 
    // Zero the local parameter value buffer.
    ZeroBytes( (u8*) &ParameterValueString[0], MAX_PARAMETER_VALUE_SIZE );
    
    // Zero the stack locations used to pass parameters to this routine.
    argc = 0;
    argv = 0;
    
    // Return the result code.
    return( result );
}

/*------------------------------------------------------------------------------
| ParseFileNameParameter
|-------------------------------------------------------------------------------
|
| PURPOSE: To parse a file name from a string and assign it to a file name
|          parameter.
|
| DESCRIPTION: Only assigns the file name if the parameter is unspecified. After
| assignment the parameter becomes specified.
| 
| The input file name parameter may have a default file name associated with
| it, in which case it will be deallocated if a new file name is assigned.
|
| HISTORY: 
|    22Feb14 Factored out of ParseCommandLine().
|    29Mar14 Revised to use ParseWordsOrQuotedPhrase() instead of
|            ParseWordOrQuotedPhrase() which was clipping multi-word phrases
|            at the first space.
------------------------------------------------------------------------------*/
    // OUT: Result code, defined by symbols starting with 'RESULT_', where 0 is
    //      no error.
u32 //
ParseFileNameParameter( 
    ParamString* FileNameParameter,
                    // Address of a string parameter that holds a file name.
                    // 
    s8*          FileNameString ) 
                    // String holding the file name to be parsed and assigned
                    // to the given file name parameter if it is unspecified.
{
    u32 v;
    s8* S;
    u32 result;
    static ParameterValueString[MAX_PARAMETER_VALUE_SIZE];
    
    // Set the default result code to be no error.
    result = RESULT_OK;

    // If the file name parameter is already specified, then just return.
    if( FileNameParameter->IsSpecified )
    {
        // Go clean up and exit from this routine.
        goto CleanUp;
    }
    
    // If the file name string is missing, then fail with a missing file name
    // error code.
    if( FileNameString == 0 )
    {
        // Print an error message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Missing file name parameter.\n" );
        }
        
        // Return error code for missing command line parameter.
        result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
 
        // Go clean up and exit from this routine.
        goto CleanUp;
    }
    
    // If the file name is invalid, then exit with an error.
    if( IsFileNameValid( FileNameString ) == 0 )
    {
        // Print an error message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Invalid file name.\n" );
        }
    
        // Return error code for an invalid log file name.
        result = RESULT_INVALID_LOG_FILE_NAME;

        // Go clean up and exit from this routine.
        goto CleanUp;
    }
                   
    // Refer to the file name with the parsing cursor 'S'.
    S = FileNameString;
    
    // Parse the word(s) or quoted phrase from a string, removing any quotes. 
    // Use 'v' to count the number of bytes in the value string parsed from the 
    // text line. 
    v = ParseWordsOrQuotedPhrase( 
            &S,   // IN/OUT: Address of the address of the current character in
                  //         the string being parsed.
                  //
            (s8*) &ParameterValueString[0],
                  // Address of the output buffer where the word or phrase 
                  // should be placed.
                  //
            MAX_PARAMETER_VALUE_SIZE );
                  // Size of the output buffer in bytes.
    
    // If the file name was parsed, then use it to replace the
    // default file name.
    if( v )
    {
        // If a default file name has been assigned to the parameter, then
        // deallocate it.
        if( FileNameParameter->Value )
        {
            // Delete the default file name.
            DeleteString( FileNameParameter->Value );
        }
        
        // Duplicate the file name parsed above and assign it to the file
        // name parameter.
        FileNameParameter->Value = 
            DuplicateString( (s8*) &ParameterValueString[0] );
    
        // Mark the file name parameter has having been specified.
        FileNameParameter->IsSpecified = 1;
    }
    else // Return an error code if the file name is missing.
    {
        // Print an error message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Missing file name parameter.\n" );
        }
        
        // Return error code for a missing command line parameter.
        result = RESULT_MISSING_COMMAND_LINE_PARAMETER;
    }
                
//////////
CleanUp://
//////////

    //--------------------------------------------------------------------------
    // Clean up the memory areas used by this routine to minimize the potential
    // for information leakage.
    //--------------------------------------------------------------------------
  
    // Zero the local variables.
    v = 0;
    S = 0;
    
    // Zero the local parameter value buffer.
    ZeroBytes( (u8*) &ParameterValueString[0], MAX_PARAMETER_VALUE_SIZE );
    
    // Zero the stack locations used to pass parameters to this routine.
    FileNameString = 0;
    FileNameParameter = 0;
    
    // Return the result code.
    return( result );
}
      
/*------------------------------------------------------------------------------
| ParseKeyIDFromKeyDefString
|-------------------------------------------------------------------------------
|
| PURPOSE: To parse the KeyID value assigned to a key definition.
|
| DESCRIPTION: A key definition in a 'key.map' file begins with a line with the
| word "KeyID", like this: "KeyID( 1844 )". The number inside the parentheses 
| identifies the definition.
|
| This routine converts the string form of the KeyID number into an integer for
| use by other crypto routines.
|
| HISTORY: 
|    01Feb14 Factored out of LookupKeyDefinitionByKeyID(). 
|    16Feb14 Revised for hash-based header design.
------------------------------------------------------------------------------*/
    // OUT: Result code: RESULT_OK on success, or an error code otherwise.
u32 //
ParseKeyIDFromKeyDefString( 
    s8*  KeyDefString,
            // A string beginning with 'KeyID', such as "KeyID( 1844 )". The 
            // string is zero-terminated ASCII.
            //
    u64* ParsedKeyID )
            // OUT: Value parsed, eg. "1844" as a binary number.
{
    u32 ByteCount;
    s8* End;
    s8* S;
     
    // This is the situation:
    //
    //     KeyDefString
    //     |
    //     v
    //     KeyID( 1844 )

    // Get the number of bytes in the string not including the zero teriminator.
    ByteCount = CountString( KeyDefString );    
            
    // Calculate the address of the first byte after the string, at the 
    // zero-terminator.
    End = KeyDefString + ByteCount;
            
    // Use S to refer to the byte following "KeyID".
    S = KeyDefString + 5;
            
    //          S
    //          |
    //          v
    //     KeyID( 1844 )
            
    // Skip over the '(' and any whitespace that follows it.
    while( (S < End) && ( IsWhiteSpace(*S) || (*S == '(') ) )
    {
        S++;
    }
            
    // If the end of the string has been reached, then return an error code.
    if( S >= End )
    {
        return( RESULT_MISSING_KEYID_IN_KEYDEF_STRING );
    }
    
    // Otherwise, some non-blank part of the string remains.
            
    //            S
    //            |
    //            v
    //     KeyID( 1844 )
            
    // Parse the number expecting it to be the KeyID.
    //
    // OUT: The value parsed from the string. The cursor S is advanced. 
    //      
    *ParsedKeyID =
        ParseUnsignedInteger(  
            &S,   // IN/OUT: Address of the address of the current character.
                  //
            End );// Address of the first byte after the buffer, a limit on how
                  // far forward scanning can go.
     
    // Return RESULT_OK to mean successful parsing of the KeyID. 
    return( RESULT_OK );
}

/*------------------------------------------------------------------------------
| ParseUnsignedInteger
|-------------------------------------------------------------------------------
| 
| PURPOSE: To parse an unsigned decimal or hexadecimal integer from a string 
|          after skipping any white space.
|
| DESCRIPTION: S is a parsing cursor that tracks the location of the current
| character in an ASCII string.
|
|    Hex integers begin with a 'x' or 'X' character, eg. "0x1fe" or "xDE12".
|
|       Entry:  *S = pointer to ASCII string.
|
|       Exit:   Return value is the parsed number.
|               *S points to the first character after the number parsed from
|               the string.
| HISTORY: 
|    26Oct13 
|    01Dec13 Added end-of-buffer to avoid scanning into other structures.
|            Extended from 32-bit to 64-bit result.
------------------------------------------------------------------------------*/
    // OUT: The value parsed from the string. The cursor at *S is advanced.
u64 //
ParseUnsignedInteger(  
    s8** S,
          // IN/OUT: Address of the address of the current character.
          //
    s8*  AfterBuffer )
          // Address of the first byte after the buffer, a limit on how far 
          // forward scanning can go.
{   
    u64 result;
    s8* Cursor;
    s8  c;
    u32 Base;
    
    // Clear the result accumulator. 
    result = 0;
    
    // Default to decimal.
    Base = 10;
    
    // Skip over any whitespace, updating *S.
    SkipWhiteSpace( S, AfterBuffer );
    
    // Refer to the current character in the string using variable Cursor.
    Cursor = *S;

//////////////
BoundsCheck://
//////////////
     
    // If the current byte is inside the buffer, then accumulate digits.
    if( Cursor < AfterBuffer )
    {
        // Fetch the current character from the string.
        c = *Cursor;
        
        // If the hex number indicator is found.
        if( c == 'x' || c == 'X' )
        {
            // Change the numeric base to base-16.
            Base = 16;
            
            // Advance to the next character.
            Cursor++;
            
            // Go get the next character.
            goto BoundsCheck;
        }
    
        // If the byte is an ASCII digit.
        if( c >= '0' && c <= '9' )
        {
            // Shift the result over byte the size of the base, and add the 
            // digit.
            result = Base * result + (c - '0');
            
            // Advance to the next character.
            Cursor++;
            
            // Go get the next character.
            goto BoundsCheck;
        }
    
        // If in base 16 and a value value between 'a' and 'f' then handle those
        // digits.
        if( Base == 16 )
        {
            // If the byte is a lowercase ASCII hex digit, accumulate the nibble
            // into the result.
            if( c >= 'a' && c <= 'f' )
            {
                result = ( result << 4 ) + ( c - 'a' + 10 );
            
                // Advance to the next character.
                Cursor++;
                
                // Go get the next character.
                goto BoundsCheck;
            }
            
            // If the byte is a uppercase ASCII hex digit, accumulate the nibble
            // into the result.
            if( c >= 'A' && c <= 'F' )
            {
                result = ( result << 4 ) + ( c - 'A' + 10 );
            
                // Advance to the next character.
                Cursor++;
                
                // Go get the next character.
                goto BoundsCheck;
            }
        }
    }
    
    // Update the parsing cursor.
    *S = Cursor;
    
    // Return the number parsed.
    return( result );
}

/*------------------------------------------------------------------------------
| ParseWordOrQuotedPhrase
|-------------------------------------------------------------------------------
|
| PURPOSE: To parse a word or quoted phrase from a string, removing any quotes.
|
| DESCRIPTION: This routine takes a parsing cursor 'S' as input which refers to
| the zero-terminated string being parsed. 
|
| The text parsed is moved to OutputBuffer and terminated with a zero byte. The 
| parsing cursor is updated to refer to the first byte after the word or quoted 
| phrase.
|
| On entry to this routine, here are three examples:
|
|    S
|    |
|    v
|    file1.key
|    'a file name with spaces.key'
|    "a file name with spaces.key"
|
| After parsing, the situation is:
|
|             S        or         S
|             |                   |
|             v                   |
|    file1.key                    v
|    'a file name with spaces.key'
|    "a file name with spaces.key"
|
| ...and the OutputBuffer holds:
|
|    [file1.key0] or [a file name with spaces.key0]
|
| HISTORY: 
|    21Feb14 
------------------------------------------------------------------------------*/
    // OUT: Number of characters in the word or phrase parsed, not counting 
    //      the terminal zero. S is updated and the result is in OutputBuffer.
u32 //
ParseWordOrQuotedPhrase( 
    s8** S, 
          // IN/OUT: Address of the address of the current character in the
          //         string being parsed.
          //
    s8* OutputBuffer,
          // Address of the output buffer where the word or phrase should be
          // placed.
          //
    u32 OutputBufferSize )
          // Size of the output buffer in bytes.
{
    s8* AfterBuffer;
    s8* s;
    s8  Delimiter;
    u32 ByteCount;
    u32 StringSize;
    
    // Start with no bytes added to the OutputBuffer.
    ByteCount = 0;
    
    // If there is no room for anything in the output buffer, then just 
    // return 0.
    if( OutputBufferSize == 0 )
    {
        return(0);
    }
      
    // Refer to the address of the first byte in the string using 's' (note
    // the lower case).
    s = *S;
    
    // If S refers to a string address of zero, then there is no string to
    // parse, so just return 0.
    if( s == 0 )
    {
        return(0);
    }
    
    // Count the number of bytes in the input string, not including the zero
    // byte that marks the end.
    StringSize = CountString( s );
    
    // If the string is empty, then just return zero as the number of bytes
    // parsed.
    if( StringSize == 0 )
    {
        return(0);
    }

    // Calcalate the address of the first byte after the string being parsed.
    AfterBuffer = s + StringSize;

    // Skip any leading whitespace before the next word or phrase.
    SkipWhiteSpace( 
        &s,
          // IN/OUT: Address of the address of the current character.
          //
        AfterBuffer );
          // Address of the first byte after the buffer, a limit on how far 
          // forward scanning can go.

    // This is the situation:
    //
    //   s
    //   |
    //   v
    //   file1.key
    //   'a file name with spaces.key'
    //   "a file name with spaces.key"
    
    // If the first byte is a ' or ", then set a flag indicating the presence of 
    // a delimited value.
    if( (*s == '\'') || (*s == '"') )
    {
        // Save the delimiter value.
        Delimiter = *s;
        
        // Advance past the delimiter.
        s++;
    }
    else // Not a delimited value.
    {
        // Use 0 to mean the parameter is not a delimited by a quote instead of 
        // a space.
        Delimiter = 0;
    }
            
    // Copy the word or phrase to the output buffer, stopping at the end of the 
    // string, when the output buffer is full, or at the appropriate delimiter.
    while( *s && 
           ( ByteCount < (OutputBufferSize - 1) ) &&
           !(
               ( (Delimiter == 0) && IsWhiteSpace(*s) ) ||
               ( (Delimiter != 0) && (*s == Delimiter) ) 
            ) )
    {
        // Copy the byte to the value buffer, advancing both pointers.
        *OutputBuffer++ = *s++;
        
        // Account for adding a byte to the OutputBuffer.
        ByteCount++;
    }
    
    // Append a string terminator byte to the output buffer.
    *OutputBuffer = 0;
    
    // If 's' points to a delimiter, and a delimiter began the phrase parsed,
    // then advance 's' by one byte.
    if( Delimiter && (*s == Delimiter) )
    {
        s++;
    }
    
    // Update the string cursor for the caller.
    *S = s;
    
    // Return the number of bytes parsed to the output buffer.
    return( ByteCount );
}

/*------------------------------------------------------------------------------
| ParseWordOrQuotedPhrasePreservingQuotes
|-------------------------------------------------------------------------------
|
| PURPOSE: To parse a word or quoted phrase from a string, preserving any 
|          quotes.
|
| DESCRIPTION: This routine takes a parsing cursor 'S' as input which refers to
| the zero-terminated string being parsed. 
|
| The text parsed is moved to OutputBuffer and terminated with a zero byte. The 
| parsing cursor is updated to refer to the first byte after the word or quoted 
| phrase.
|
| On entry to this routine, here are three examples:
|
|    S
|    |
|    v
|    file1.key
|    'a file name with spaces.key'
|    "a file name with spaces.key"
|
| After parsing, the situation is:
|
|             S        or         S
|             |                   |
|             v                   |
|    file1.key                    v
|    'a file name with spaces.key'
|    "a file name with spaces.key"
|
| ...and the OutputBuffer holds:
|
|    [file1.key0] or ["a file name with spaces.key"0]
|
| HISTORY: 
|    23Mar14 From ParseWordOrQuotedPhrase().
------------------------------------------------------------------------------*/
    // OUT: Number of characters in the word or phrase parsed, not counting 
    //      the terminal zero. S is updated and the result is in OutputBuffer.
u32 //
ParseWordOrQuotedPhrasePreservingQuotes( 
    s8** S, 
          // IN/OUT: Address of the address of the current character in the
          //         string being parsed.
          //
    s8* OutputBuffer,
          // Address of the output buffer where the word or phrase should be
          // placed.
          //
    u32 OutputBufferSize )
          // Size of the output buffer in bytes.
{
    s8* AfterBuffer;
    s8* s;
    s8  Delimiter;
    u32 ByteCount;
    u32 StringSize;
    
    // Start with no bytes added to the OutputBuffer.
    ByteCount = 0;
    
    // If there is no room for anything in the output buffer, then just 
    // return 0.
    if( OutputBufferSize == 0 )
    {
        return(0);
    }
      
    // Refer to the address of the first byte in the string using 's' (note
    // the lower case).
    s = *S;
    
    // If S refers to a string address of zero, then there is no string to
    // parse, so just return 0.
    if( s == 0 )
    {
        return(0);
    }
    
    // Count the number of bytes in the input string, not including the zero
    // byte that marks the end.
    StringSize = CountString( s );
    
    // If the string is empty, then just return zero as the number of bytes
    // parsed.
    if( StringSize == 0 )
    {
        return(0);
    }

    // Calcalate the address of the first byte after the string being parsed.
    AfterBuffer = s + StringSize;

    // Skip any leading whitespace before the next word or phrase.
    SkipWhiteSpace( 
        &s,
          // IN/OUT: Address of the address of the current character.
          //
        AfterBuffer );
          // Address of the first byte after the buffer, a limit on how far 
          // forward scanning can go.

    // This is the situation:
    //
    //   s
    //   |
    //   v
    //   file1.key
    //   'a file name with spaces.key'
    //   "a file name with spaces.key"
    
    // If the first byte is a ' or ", then set a flag indicating the presence of 
    // a delimited value.
    if( (*s == '\'') || (*s == '"') )
    {
        // Save the delimiter value.
        Delimiter = *s;
        
        // Copy the byte to the value buffer, advancing both pointers.
        *OutputBuffer++ = *s++;
        
        // Account for adding a byte to the OutputBuffer.
        ByteCount++;
    }
    else // Not a delimited value.
    {
        // Use 0 to mean the parameter is not a delimited by a quote instead of 
        // a space.
        Delimiter = 0;
    }
            
    // Copy the word or phrase to the output buffer, stopping at the end of the 
    // string, when the output buffer is full, or at the appropriate delimiter.
    while( *s && 
           ( ByteCount < (OutputBufferSize - 1) ) &&
           !(
               ( (Delimiter == 0) && IsWhiteSpace(*s) ) ||
               ( (Delimiter != 0) && (*s == Delimiter) ) 
            ) )
    {
        // Copy the byte to the value buffer, advancing both pointers.
        *OutputBuffer++ = *s++;
        
        // Account for adding a byte to the OutputBuffer.
        ByteCount++;
    }
    
    // If a delimiter is used and the loop ended at a delimiter, then copy the
    // final delimiter to the output buffer.
    if( Delimiter && (*s == Delimiter) )
    {
        // Copy the byte to the value buffer, advancing both pointers.
        *OutputBuffer++ = *s++;
        
        // Account for adding a byte to the OutputBuffer.
        ByteCount++;
    }
    
    // Append a string terminator byte to the output buffer.
    *OutputBuffer = 0;
     
    // Update the string cursor for the caller.
    *S = s;
    
    // Return the number of bytes parsed to the output buffer.
    return( ByteCount );
}

/*------------------------------------------------------------------------------
| ParseWordsOrQuotedPhrase
|-------------------------------------------------------------------------------
|
| PURPOSE: To parse several words or a quoted phrase from a string, removing any 
|          quotes.
|
| DESCRIPTION: This routine takes a parsing cursor 'S' as input which refers to
| the zero-terminated string being parsed. 
|
| The text parsed is moved to OutputBuffer and terminated with a zero byte. The 
| parsing cursor is updated to refer to the first byte after the words or 
| quoted phrase.
|
| Parses words until the end of the string is reached or until the second 
| delimiter if there are delimiters.
|
| Leading and trailing spaces are significant if the first character is not a
| delimiter.
|
| On entry to this routine, here are three examples:
|
|    S
|    |
|    v
|    a file name with spaces.key
|    'a file name with spaces.key'
|    "a file name with spaces.key"
|
| After parsing, the situation is:
|
|                               S S
|                               | |
|                               v |
|    a file name with spaces.key  v
|    'a file name with spaces.key'
|    "a file name with spaces.key"
|
| ...and the OutputBuffer holds:
|
|    [a file name with spaces.key0]
|
| HISTORY: 
|    29Mar14 From ParseWordOrQuotedPhrase().
------------------------------------------------------------------------------*/
    // OUT: Number of characters in the word or phrase parsed, not counting 
    //      the terminal zero. S is updated and the result is in OutputBuffer.
u32 //
ParseWordsOrQuotedPhrase( 
    s8** S, 
          // IN/OUT: Address of the address of the current character in the
          //         string being parsed.
          //
    s8* OutputBuffer,
          // Address of the output buffer where the word or phrase should be
          // placed.
          //
    u32 OutputBufferSize )
          // Size of the output buffer in bytes.
{
    s8* AfterBuffer;
    s8* s;
    s8  Delimiter;
    u32 ByteCount;
    u32 StringSize;
    
    // Start with no bytes added to the OutputBuffer.
    ByteCount = 0;
    
    // If there is no room for anything in the output buffer, then just 
    // return 0.
    if( OutputBufferSize == 0 )
    {
        return(0);
    }
      
    // Refer to the address of the first byte in the string using 's' (note
    // the lower case).
    s = *S;
    
    // If S refers to a string address of zero, then there is no string to
    // parse, so just return 0.
    if( s == 0 )
    {
        return(0);
    }
    
    // Count the number of bytes in the input string, not including the zero
    // byte that marks the end.
    StringSize = CountString( s );
    
    // If the string is empty, then just return zero as the number of bytes
    // parsed.
    if( StringSize == 0 )
    {
        return(0);
    }

    // Calcalate the address of the first byte after the string being parsed.
    AfterBuffer = s + StringSize;
 
    // This is the situation:
    //
    //   s
    //   |
    //   v
    //   a file name with spaces.key
    //   'a file name with spaces.key'
    //   "a file name with spaces.key"
    
    // If the first byte is a ' or ", then set a flag indicating the presence of 
    // a delimited value.
    if( (*s == '\'') || (*s == '"') )
    {
        // Save the delimiter value.
        Delimiter = *s;
        
        // Advance past the delimiter.
        s++;
    }
    else // Not a delimited value.
    {
        // Use 0 to mean the parameter is not a delimited by a quote instead of 
        // a space.
        Delimiter = 0;
    }
            
    // Copy the words or delimited phrase to the output buffer, stopping at the 
    // end of the string, when the output buffer is full, or at the appropriate 
    // delimiter.
    while( *s && 
           ( ByteCount < (OutputBufferSize - 1) ) &&
           !( (Delimiter != 0) && (*s == Delimiter) ) )
    {
        // Copy the byte to the value buffer, advancing both pointers.
        *OutputBuffer++ = *s++;
        
        // Account for adding a byte to the OutputBuffer.
        ByteCount++;
    }
     
    // Append a string terminator byte to the output buffer.
    *OutputBuffer = 0;
    
    // If 's' points to a delimiter, and a delimiter began the phrase parsed,
    // then advance 's' by one byte.
    if( Delimiter && (*s == Delimiter) )
    {
        s++;
    }
    
    // Update the string cursor for the caller.
    *S = s;
    
    // Return the number of bytes parsed to the output buffer.
    return( ByteCount );
}

/*------------------------------------------------------------------------------
| PickKeyID
|-------------------------------------------------------------------------------
|
| PURPOSE: To pick a KeyID to be used for an OT7 header. 
|
| DESCRIPTION: Picks a number from the range specified in a key definition. If
| several values are possible, then the key file will be read to supply a 
| random number used to pick a random KeyID.
|
| HISTORY: 
|    20Jan14 From SelectFillSize(). 
------------------------------------------------------------------------------*/
// OUT: KeyID.IsSpecified will be set to 1 if KeyID.Value was validly assigned.
void
PickKeyID( 
    Param* KeyID,
        // The KeyID parameter to be set.   
        //
    FILE*  KeyFileHandle,
        // The key file. Some of the random data from this file may be read to 
        // pick a value in the range defined by FirstKeyID and LastKeyID.
        //
    u64 FirstKeyID, 
        // Low end of a range of possible KeyID values.
        //
    u64 LastKeyID ) 
        // High end of a range of possible KeyID values.
{
    u32 BytesRead;
    u64 RandomValue;
    u64 RangeSize;
    
    // If the range of KeyID's to use is limited to a single value, then use 
    // that value.
    if( FirstKeyID == LastKeyID )
    {
        KeyID->Value = FirstKeyID;
        
        // Mark the KeyID as specified.
        KeyID->IsSpecified = 1;
    }
    else // Several KeyID values are possible.
    {
        // Read a 64-bit random number from the one-time pad file.
        BytesRead = ReadU64( KeyFileHandle, &RandomValue );
        
        // If unable to 8 bytes from the key file, then return without 
        // setting the KeyID->IsSpecified = 1.
        if( BytesRead != 8 )
        {
            return;
        }
        
        // Calculate the size of the range of KeyID numbers possible where
        // the LastKeyID is included in the range.
        RangeSize = (LastKeyID - FirstKeyID) + 1;
   
        // Randomly generate an offset from the FirstKeyID and add it to the
        // FirstKeyID.
        KeyID->Value = FirstKeyID + (RandomValue % RangeSize);
        
        // Mark the KeyID as specified.
        KeyID->IsSpecified = 1;
    }
}

/*------------------------------------------------------------------------------
| PrintStringList
|-------------------------------------------------------------------------------
|
| PURPOSE: To print a zero-terminated list of strings.
|
| DESCRIPTION: Each string is printed on a separate line to standard output.
|
| EXAMPLE:  
|
|    s8* ColorList[] = { "Red", "Green", "Blue", 0 };
|
|    PrintStringArray( ColorList );
|    
| HISTORY: 
|    27Oct13 
------------------------------------------------------------------------------*/
void
PrintStringList( s8** AStringList )
{
    s8* AString;
     
    while( 1 )
    {
        // Get the address of the next string in the array of string addresses.
        AString = *AStringList++;
        
        // If there are no more strings, then just return.
        if( AString == 0 )
        {
            return;
        }
        
        // Print the string with an end-of-line so that each string is printed
        // on a separate line.
        printf( "%s\n", AString );
    }
}

/*------------------------------------------------------------------------------
| Put_u16_LSB_to_MSB
|-------------------------------------------------------------------------------
|
| PURPOSE: To store a 16-bit integer to a buffer in LSB-to-MSB order.
|
| DESCRIPTION: This puts integers into a standard byte order regardless of what
| kind of CPU this code is running on. 
|
| HISTORY: 
|    26Dec13 From Put_u32_LSB_to_MSB().
------------------------------------------------------------------------------*/
void
Put_u16_LSB_to_MSB( u16 n, u8* Buffer )
{
    // Put the bytes in LSB-to-MSB order.
    Buffer[0] = (u8) n; n >>= 8;
    Buffer[1] = (u8) n; 
}

/*------------------------------------------------------------------------------
| Put_u32_LSB_to_MSB
|-------------------------------------------------------------------------------
|
| PURPOSE: To store a 32-bit integer to a buffer in LSB-to-MSB order.
|
| DESCRIPTION: This puts integers into a standard byte order regardless of what
| kind of CPU this code is running on. 
|
| HISTORY: 
|    03Nov13 From WriteU32().
------------------------------------------------------------------------------*/
void
Put_u32_LSB_to_MSB( u32 n, u8* Buffer )
{
    // Put the bytes in LSB-to-MSB order.
    Buffer[0] = (u8) n; n >>= 8;
    Buffer[1] = (u8) n; n >>= 8; 
    Buffer[2] = (u8) n; n >>= 8; 
    Buffer[3] = (u8) n;  
}

/*------------------------------------------------------------------------------
| Put_u64_LSB_to_MSB
|-------------------------------------------------------------------------------
|
| PURPOSE: To store a 64-bit integer to a buffer in LSB-to-MSB order.
|
| DESCRIPTION: This puts integers into a standard byte order regardless of what
| kind of CPU this code is running on. 
|
| HISTORY: 
|    09Nov13 From Put_u32_LSB_to_MSB().
------------------------------------------------------------------------------*/
void
Put_u64_LSB_to_MSB( u64 n, u8* Buffer )
{
    // Put the 8 bytes of n in LSB-to-MSB order to the buffer.
    Buffer[0] = (u8) n; n >>= 8;
    Buffer[1] = (u8) n; n >>= 8; 
    Buffer[2] = (u8) n; n >>= 8; 
    Buffer[3] = (u8) n; n >>= 8;
    Buffer[4] = (u8) n; n >>= 8;
    Buffer[5] = (u8) n; n >>= 8; 
    Buffer[6] = (u8) n; n >>= 8;
    Buffer[7] = (u8) n;   
}

/*------------------------------------------------------------------------------
| Put_u64_LSB_to_MSB_WithTruncation
|-------------------------------------------------------------------------------
|
| PURPOSE: To store a 64-bit integer to a buffer in LSB-to-MSB order with
|          optional truncation of the more-significant bytes.
|
| DESCRIPTION: This puts integers into a standard byte order regardless of what
| kind of CPU this code is running on. It also may trim off the leading zeros 
| of large numbers that are not significant.
|
| The ByteCount parameter limits the number of bytes written to the buffer to
| be no more than ByteCount. See NumberOfSignificantBytes() for how to measure
| the number of significant bytes in an unsigned 64-bit number.
|
| HISTORY: 
|    09Nov13 From Put_u32_LSB_to_MSB().
------------------------------------------------------------------------------*/
void
Put_u64_LSB_to_MSB_WithTruncation( u64 n, u8* Buffer, u8 ByteCount )
{
    // Limit ByteCount to the size of the integer.
    if( ByteCount > sizeof(u64) )
    {
        ByteCount = sizeof(u64);
    }
    
    // Put the bytes of n in LSB-to-MSB order to the buffer.
    while( ByteCount-- )
    {
        // Copy the current least-significant byte of the integer to the
        // buffer, advancing the buffer pointer by one byte.
        *Buffer++ = (u8) n; 
        
        // Shift the integer to the right by 8 bits.
        n >>= 8;
    }
}
 
/*------------------------------------------------------------------------------
| Read6BitWordX
|-------------------------------------------------------------------------------
|
| PURPOSE: To read a byte containing the next 6-bit word found in the base64 
|          file, ignoring any whitespace. 
|
| DESCRIPTION: Leaves the 6-bit word read in AByte, BByte, or CByte. Returns 
| the 6-bit value or -1 if there was an error or EOF.
|
| This routine assumes the file has been opened for reading base64 such that 
| F->FileFormat == OT7_FILE_FORMAT_BASE64.
|
| HISTORY:  
|    10Nov13 From WriteByteX().
|    28Feb14 Changed variable name Letter to ByteRead, changed LastLetterRead to
|            LastSymbolRead. Fixed bugs in interpreting lowercase letters and
|            digits.
------------------------------------------------------------------------------*/
    // OUT: Returns the 6-bit value or -1 if there was an error or EOF.
s16 //
Read6BitWordX( FILEX* F )
{
    u8  ByteRead;
    u8  SixBits;
    u8  WordIndex;
    u32 NumberRead;
    
    // If the last base64 character read is padding byte ('='), then return -1 
    // to signal EOF. Assume here that the base64 sequence was encoded from
    // byte sequences which are completed by the reception of a single '='
    // padding byte.
    if( F->LastSymbolRead == BASE64_PAD_CHAR )
    {
        return( -1 );
    }
    
///////////////
ReadNextByte://
///////////////
     
    // Read the next byte from the underlying file, expecting it to be a letter
    // in the base64 alphabet or whitespace.
    //
    // Returns the number of bytes read, or MAX_VALUE_32BIT if error or EOF.
    NumberRead = ReadByte( F->FileHandle, &ByteRead );
    
    // If the number of bytes read is not 1, then return -1 to signal an error 
    // or EOF.
    if( NumberRead != 1 )
    {
        return( -1 );
    }
    
    // Advance the current file position by 1.
    F->FilePositionInBytes++;
    
    // If the byte read is not a symbol in the base64 alphabet, then go read 
    // the next byte.
    if( IsBase64(ByteRead) == 0 )
    {
        goto ReadNextByte;
    }
    
    // Keep track of the last base64 letter read for completing the stream
    // when there are padding bytes ('=') at the end.
    F->LastSymbolRead = ByteRead;
    
    // If the byte read is a base64 padding byte ('='), then use zero as the
    // value of the 6-bit word read.
    if( ByteRead == BASE64_PAD_CHAR )
    {
        SixBits = 0;
    } 
    else // Use formulas equivalent to the base64 alphabet table to convert the 
         // byte read to a 6-bit value. See base64Alphabet[].
    {
        // If the byte read is an uppercase letter, then subtract ASCII 'A' to 
        // get the value of the 6-bit word.
        if( (ByteRead >= 'A') && (ByteRead <= 'Z') )
        {
            SixBits = ByteRead - 'A';
        } 
        else // Not an uppercase letter.
        {
            // If the byte read is a lowercase letter, then subtract ASCII 'a' 
            // and add 26 to get the value of the 6-bit word.
            if( (ByteRead >= 'a') && (ByteRead <= 'z') )
            {
                SixBits = (ByteRead - 'a') + 26;
            } 
            else // Not uppercase or lowercase letter.
            {
                // If the letter is a digit, then subtract the ASCII '0' and
                // add 52 to get the value of the 6-bit word.
                if( (ByteRead >= '0') && (ByteRead <= '9') )
                {
                    SixBits = (ByteRead - '0') + 52;
                } 
                else // Not a letter or digit.
                {
                    // If the letter is '+', then use 62 for the value of the 
                    // 6-bit word.
                    if( ByteRead == '+' )
                    {
                        SixBits = 62;
                    } 
                    else // It must be a '/', so use 63 as the value.
                    {
                        SixBits = 63;
                    }
                }
            }
        }
    }
                           
    // In base64 encoding, 6-bit words are packed into bytes using a 4-in-3 byte 
    // arrangement as shown here:
    //
    //         word index=1
    //               |
    //            -------
    //      00000011 11112222 22333333  
    //       AByte    BByte    CByte
    //
    // where: 
    //
    //      000000 is the first 6-bit word, 111111 is the second, and 
    //             so on.
    
    // Compute which of the four positions in a 24-bit group will be filled in 
    // next based on how many 6-bit words have been read from the file so far.
    // 
    // FilePositionIn6BitWords is the current offset from the beginning of the 
    // file in terms of 6-bit words, ignoring whitespace and padding.
    //
    // The least significant two bits of the 6-bit-word file position is a word 
    // index that refers to a 6-bit word in a 24-bit field.
    WordIndex = (u8) (F->FilePositionIn6BitWords & 3);
    
    // Advance the 6-bit word file position by one to account for the 6-bit 
    // word read in this routine.
    F->FilePositionIn6BitWords++;
             
    // Handle each of the four positions separately.
    switch( WordIndex )
    {
        case 0:
        {
            //      ======
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // Store the 6-bit word in AByte, aligned according to the above
            // diagram.
            F->AByte &= 3;
            F->AByte |= SixBits << 2;
            
            // All done with this case, skip over the other cases.
            break;
        }
                
        //----------------------------------------------------------------------
                  
        case 1:
        {
            //            =======
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // Split the 6-bit word, storing it in AByte and BByte, aligned 
            // according to the above diagram.
            F->AByte &= ~3;
            F->AByte |= SixBits >> 4;
           
            F->BByte &= 0x0F;
            F->BByte |= SixBits << 4;
             
            // All done with this case, skip over the other cases.
            break;
        }
                
        //----------------------------------------------------------------------
                 
        case 2:
        {
            //                   =======
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // Split the 6-bit word, storing it in BByte and CByte, aligned 
            // according to the above diagram.
            F->BByte &= 0xF0;
            F->BByte |= SixBits >> 2;
           
            F->CByte &= 0x3F;
            F->CByte |= SixBits << 6;
             
            // All done with this case, skip over the other cases.
            break;
        }
                
        //----------------------------------------------------------------------
                 
        case 3:
        {
            //                          ======
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // Store the 6-bit word CByte, aligned according to the above 
            // diagram.
           
            F->CByte &= ~0x3F;
            F->CByte |= SixBits;
             
            // All done with this case.
            break;
        }
                 
    } // switch( WordIndex )
  
    // Return the value of the 6-bit word.
    return( (s16) SixBits );
}

/*------------------------------------------------------------------------------
| ReadByte
|-------------------------------------------------------------------------------
|
| PURPOSE: To read a byte from a file to a buffer.
|
| DESCRIPTION: Returns the number of bytes read, or MAX_VALUE_32BIT (0xFFFFFFFF)
| if error or EOF.
|
| HISTORY:  
|    02Feb89
|    21Dec89 revised to pass error code
|    19Oct13 Revised for changes made to ReadBytes().
|    07Nov13 Changed return value passing to follow same format as ReadBytes().
------------------------------------------------------------------------------*/
    // OUT: Returns the number of bytes read, or MAX_VALUE_32BIT if error or 
    //      EOF.
u32 //
ReadByte( FILE*  FileHandle,
                    // Handle to an open file.
                    //
          u8*    BufferAddress )
                    // Destination buffer for the data read from the file.
{
    // Read one byte to the destination buffer, returning the number of bytes 
    // read, or MAX_VALUE_32BIT (0xFFFFFFFF) on error or EOF.
    return( ReadBytes( FileHandle, BufferAddress, 1 ) );
}
 
/*------------------------------------------------------------------------------
| ReadBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To read bytes from a file to a buffer.
|
| DESCRIPTION: Returns the number of bytes read, or 0xFFFFFFFF if error or EOF.
|
| HISTORY: 
|    05Oct13 Changed byte sizes to unsigned, and changed return value from -1 to
|            0xFFFFFFFF.
------------------------------------------------------------------------------*/
    // OUT: Returns the number of bytes read, or MAX_VALUE_32BIT if error or 
    //      EOF.
u32 //
ReadBytes( FILE*  FileHandle,
                    // Handle to an open file.
                    //
           u8*    BufferAddress,
                    // Destination buffer for the data read from the file.
                    //
           u32    NumberOfBytes )
                    // Number of bytes to read.
{
    u32 Result;
    
    // Read the specified number of bytes from the given file to the buffer.
    Result = (u32) fread( BufferAddress,                                  
                          1,
                          NumberOfBytes,
                          FileHandle );

    // If the number of bytes is less than the number requested, then an error
    // or EOF has occurred.            
    if( Result < NumberOfBytes )
    {
        // Return the error code MAX_VALUE_32BIT (0xFFFFFFFF).
        return( MAX_VALUE_32BIT );
    }

    // Return the number of bytes read.
   return( Result );
}

/*------------------------------------------------------------------------------
| ReadBytesX
|-------------------------------------------------------------------------------
|
| PURPOSE: To read bytes from a file in either binary or base64 format.
|
| DESCRIPTION: Returns number of bytes read.
|
| EXAMPLE: Given an open file with a properly positioned file pointer, read 15 
| bytes from the file to buffer ABuffer.
|
|              NumberRead = ReadBytesX( FileHandle, ABuffer, 15 );
| HISTORY: 
|    30Nov13 From WriteBytesX() and ReadBytes().
------------------------------------------------------------------------------*/
    // OUT: Number of bytes read.
u32 //
ReadBytesX( FILEX* F,
                    // Extended file handle of an open file.
                    //
            u8* BufferAddress,
                    // Destination buffer for the data read from the file.
                    //
            u32 NumberOfBytes )
                    // Number of bytes to read.
{
    u32 i;
    u32 NumberRead;

    // Start with no bytes read.
    NumberRead = 0;
    
    // Read the bytes in the form specified by the file format.
    switch( F->FileFormat )
    {
        case OT7_FILE_FORMAT_BINARY:
        {
            // If a file handle is given and the number of bytes to read is
            // non-zero, then read the bytes.
            if( F->FileHandle && NumberOfBytes )
            {    
                // Read the specified number of bytes from the given file to 
                // the buffer.
                NumberRead = (u32) 
                    fread( BufferAddress,
                           1,
                           NumberOfBytes,
                           F->FileHandle );
                           
                // Advance the file position by the number of bytes read.
                F->FilePositionInBytes += (u64) NumberRead;
            }
         
            // Go to the exit.
            break;
        } 
        
        //----------------------------------------------------------------------
    
        // If reading in base64 format, then read ASCII characters and translate
        // to binary. 
        case OT7_FILE_FORMAT_BASE64:
        {
            // Read each of the bytes to the buffer up to the given limit.
            for( i = 0; i < NumberOfBytes; i++ )
            {
                // If the byte was read successfully, then increment the
                // number of bytes read.
                if( ReadByteX( F, &BufferAddress[i] ) )
                {
                    NumberRead++;
                } 
                else // Unable to read the byte.
                {
                    // Skip the rest of the buffer and go to the exit.
                    goto Exit;
                }
            }
        }
    }
    
///////
Exit://
///////
        
    // Return the number of bytes read.
    return( NumberRead );
}

/*------------------------------------------------------------------------------
| ReadByteX
|-------------------------------------------------------------------------------
|
| PURPOSE: To read a binary byte from a file encoded in either base64 or binary
|          format.
|
| DESCRIPTION: Returns the number of bytes read. In translating input bytes to
| binary, some reduction may occur: more than one byte may need to be read from 
| the file in order to produce one binary byte. This routine handles the 
| details.
|
| EXAMPLE: Read a byte from an open file at the current file position.
|
|             NumberRead = ReadByteX( AFileHandle, &ByteBuffer );
| 
| On return, NumberRead will be 1 unless there is an error or end of file.
|
| HISTORY:  
|    06Nov13 From WriteByteX().
|    26Feb14 Fixed several bugs in the base64 format code.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes read: either 1 or 0 if there was an error or EOF.
u32 //
ReadByteX( FILEX* F, u8* ByteBuffer )
{
    s16 SixBits;
    u8  WordIndex;
    u32 NumberRead;
    
    // Start with no bytes read.
    NumberRead = 0;
      
    // Read the byte according to the form specified by the file format.
    switch( F->FileFormat )
    {
        // If readign in binary format, then call the ordinary byte read 
        // routine.
        case OT7_FILE_FORMAT_BINARY:
        {
            // Read a byte, returning the number of bytes read, or 
            // MAX_VALUE_32BIT if there was an error or EOF.
            NumberRead = ReadByte( F->FileHandle, ByteBuffer );
            
            // If the byte was not read, then leave the output buffer unchanged
            // and return 0 to mean there was an error or EOF.
            if( NumberRead != 1 )
            {
                // Change the return value to 0 to mean no byte was read.
                NumberRead = 0;
            } 
            
            // Advance the file position by the number of bytes read.
            F->FilePositionInBytes += (u64) NumberRead;
         
            // Go to the exit.
            break;
        } 
        
        //----------------------------------------------------------------------
    
        // If reading in base64 format, then read ASCII characters and translate 
        // to binary.
        case OT7_FILE_FORMAT_BASE64:
        {
            // In base64 encoding, 6-bit words are packed into bytes using a
            // 4-in-3 byte arrangement as shown here:
            //
            //         word index=1
            //               |
            //            -------
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // where: 
            //
            //      000000 is the first 6-bit word, 111111 is the second, and 
            //             so on.
 
            // Compute which of the four positions in a 24-bit group will be
            // read in next based on how many 6-bit words have been read from 
            // the file so far.
            // 
            // FilePositionIn6BitWords is the current offset from the beginning 
            // of the file in terms of 6-bit words, ignoring whitespace and 
            // padding.
            //
            // The least significant two bits of the 6-bit-word file position 
            // is a word index that refers to a 6-bit word in a 24-bit field.
            WordIndex = (u8) (F->FilePositionIn6BitWords & 3);
            
            // Always read a 6-bit word here because an output of an 8-bit byte
            // entails reading at least one 6-bit word and sometimes two.
            
            // Read a 6-bit word to AByte.
            SixBits = Read6BitWordX( F );
        
            // If the 6-bit word was not read, then leave the output buffer 
            // unchanged and return 0 to mean there was an error or EOF.
            if( SixBits == -1 )
            {
                goto Exit;
            }
                        
            // Handle each of the four positions separately.
            switch( WordIndex )
            {
                case 0: 
                {
                    // Now the top 6-bits of AByte contain valid data, but the
                    // low two bits are needed. 
                    // 
                    //      ======
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                    
                    // Go read the next 6-bit word as Case 1 to complete AByte.
                    SixBits = Read6BitWordX( F );
                
                    // If the 6-bit word was not read, then leave the output 
                    // buffer unchanged and return 0 to mean there was an error 
                    // or EOF.
                    if( SixBits == -1 )
                    {
                        goto Exit;
                    }
                    
                    // Now AByte and 4-bits of BByte contain valid data.
                    // 
                    //      ======== ==== 
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                    
                    // Pass back the result in the byte buffer.
                    *ByteBuffer = F->AByte;
                       
                    // All done with this case, skip over the other cases.
                    break;
                }
                 
                //--------------------------------------------------------------
                 
                case 1:
                {
                    // Now AByte and the top 4-bits of BByte contain valid data.
                    // 
                    //      ======== ====
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                       
                    // Pass back the result in the AByte byte buffer.
                    *ByteBuffer = F->AByte;
                       
                    // All done with this case, skip over the other cases.
                    break;
                }
                
                //--------------------------------------------------------------
                 
                case 2:  
                {
                    // Now BByte contains valid data.
                    // 
                    //               ======== ==
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                      
                    // Pass back the result in the byte buffer.
                    *ByteBuffer = F->BByte;
                       
                    // All done with this case, skip over the other cases.
                    break;
                }
                    
                //--------------------------------------------------------------
                 
                case 3:  
                {
                    // Now CByte contain valid data.
                    // 
                    //                        ========
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                     
                    // Pass back the result in the byte buffer.
                    *ByteBuffer = F->CByte;
                      
                    // All done with this case, skip over the other cases.
                    break;
                }
                
            } // switch( WordIndex )
            
            // Return that 1 output byte has been read.
            NumberRead = 1;
            
         } // switch( WordIndex )
            
    } // switch( X->FileFormat )

///////
Exit://
///////
 
    // Return the number of bytes written: either 1 or 0 if there was an error.
    return( NumberRead );
}

/*------------------------------------------------------------------------------
| ReadKeyMap
|-------------------------------------------------------------------------------
|
| PURPOSE: To read an OT7 'key.map' file into a linked list of zero-terminated 
|          strings.
|
| DESCRIPTION: This routine reads information used to organize encryption keys. 
|
| The data from the file is preprocessed to strip out comments and whitespace 
| to make parsing of the contents easier.
|
| Returns the address of the list, or 0 if unable to open the file.
|
| HISTORY: 
|    24Nov13  
|    20Jan14 Revised to append items read to an input list. This permits the
|            reading of several key map files to make one large map in memory.
------------------------------------------------------------------------------*/
void
ReadKeyMap( s8* AFileName,
                    // Name of the key map file, defaulting to 'key.map'.
                    //
            List* KeyMapStringList ) 
                    // IN/OUT: List of strings from the 'key.map' file, each 
                    //         line is a separate string.
{
    List* L;
    
    // Read the key map file into memory as a linked list of strings, one per
    // line.
     L = ReadListOfTextLines( AFileName );
     
    // If data was read from the file, then strip out the bytes not required
    // for machine processing.
    if( L )
    {
        // Strip out all white space characters at the beginning of each line.
        StripLeadingWhiteSpaceInStringList( L );
        
        // Strip out all white space characters at the end of each line.
        StripTrailingWhiteSpaceInStringList( L );
        
        // Strip out all comments beginning with the characters '//'.
        StripCommentsInStringList( L );
        
        // Delete all lines that now refer to empty strings.
        DeleteEmptyStringsInStringList( L );
        
        // Transfer the items from list produced by ReadListOfTextLines() to
        // the end of the input list. This leaves L as an empty list.
        AppendItems( KeyMapStringList, L );
        
        // Deallocate the now empty list used for reading data from the file.
        DeleteList( L );
    }
}

/*------------------------------------------------------------------------------
| ReadListOfTextLines
|-------------------------------------------------------------------------------
|
| PURPOSE: To read a text file into a linked list of zero-terminated strings.
|
| DESCRIPTION: Each line is copied into a separate dynamically allocated 
| buffer, stripping off end-of-line characters, and appending a zero to complete
| the string.
|
| Each string is referenced as an item in a linked list.
|
| Strings are held in separate buffers to make it easy to resize individual 
| strings.
|
| Returns the address of the list, or 0 if unable to open the file.
|
| EXAMPLE:  
|                  AList = ReadListOfTextLines("MyData.txt");
| ASSUMES: 
|
|    List will be deleted using DeleteListOfDynamicData().
|
| HISTORY: 
|    11Dec93 
|    08Mar94 open file error check added.
|    09Jul97 changed to ReadTextLine() from ReadMacTextLine().
|    17Nov13 Revised to support large files, added comments.
------------------------------------------------------------------------------*/
        // OUT: Address of a linked list control block, or 0 if unable to make
        //      a list of strings.
List*    //
ReadListOfTextLines( s8* AFileName )
{
    List* AList;
    Item* AnItem;
    FILE* AFile;
    s16   ByteCount;
    s8*   AString;
    
    // Open the file for read-only access.
    AFile = fopen64( AFileName, "rb" );

    // If unable to open the file, return 0.
    if( AFile == 0 )
    {
        return(0);
    }

    // Allocate a linked list control block.
    AList = MakeList();
    
    // If unable to allocate a list record, then close the file and exit.
    if( AList == 0 )
    {
        goto Finish;
    }

    // Continue reading lines until the end of the file is reached or memory
    // is exhausted.
    while(1)
    {
        // Read a line of text from the file into a temporary line buffer
        // where it is formatted as a standard C string. Returns the string 
        // length, not counting the zero-terminator, or -1 at end-of-file.
        ByteCount = ReadTextLine( 
                        AFile, 
                        &TextLineBuffer[0], 
                        TEXT_LINE_BUFFER_SIZE );
            
        // If the end of the file has been reached, or a line buffer overflow, 
        // then finish up.
        if( ByteCount == -1 ) 
        {
            goto Finish;
        }
            
        // Copy the string to its own dynamically allocated buffer.
        AString = DuplicateString( &TextLineBuffer[0] );
        
        // If a new string was allocated, then append it to the list.
        if( AString )
        {
             // Append the new string to the list.
            AnItem = InsertDataLastInList( AList, (u8*) AString );
            
            // If unable to allocate an Item record for the string, then
            // delete the list and exit.
            if( AnItem == 0 )
            {
                goto OutOfMemory;
            }
        }
        else // Out of memory.
        {
//////////////
OutOfMemory://
//////////////

            // Deallocate the list of strings made so far.
            DeleteListOfDynamicData( AList );
            
            // Set AList to zero for the return value.
            AList = 0;
            
            // And go close the file.
            goto Finish;
        }
    }
     
/////////   
Finish://
/////////
   
       // Close the text file.
    fclose(AFile);
    
    // Return the list of text lines.
    return(AList);
}

/*------------------------------------------------------------------------------
| ReadTextLine
|-------------------------------------------------------------------------------
|
| PURPOSE: To read a line of text from a Windows, Mac, or Unix file.
|
| DESCRIPTION: Reads the next line from a file to a buffer where the end-of-line 
| sequence is stripped off and replaced with a zero string terminator byte.
|
| Returns the number of bytes in the line read, not counting the 
| zero-terminator.
|
| If the line is empty then 0 is returned.
|
| If end-of-file is reached then -1 is returned.
|
| If the end of the line buffer is reached before the end of the line in the
| file, then -1 is returned.
|
| If a Control Z character is encountered it is treated as an end-of-file 
| marker.
|
| EXAMPLE:     ByteCount = ReadTextLine( F, MyBuffer, BufferSize );
|
| HISTORY: 
|    09Jul97 from 'ReadMacTextLine'.
|    15Jul97 added ability to terminate lines with LineFeed.
|    08Feb01 Added Unix text line and converted ReadByte to fgetc.
|    17Nov13 Added line buffer overflow check.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes in the line read, not counting the zero-terminator,
    //      or returns -1 at end-of-file or line buffer overflow.
s32 //
ReadTextLine( 
    FILE* AFile, 
            // A text file open in the mode for reading binary data.
            //
    s8*   ABuffer,
            // Buffer where the line of text should be placed as a zero-
            // terminated string.
            //
    u32   BufferSize )
            // Size of the buffer in bytes.
{
    s32 ByteBuffer;
    s32 AByteCount;
    
    // Start with no bytes in the output buffer.
    AByteCount = 0;

///////////////
ReadNextByte://
///////////////
    
    // Read the next byte from the file.
    ByteBuffer = fgetc( AFile );
    
    // If an end-of-file has been encountered, then finish up.
    if( (ByteBuffer == EOF) || (ByteBuffer == ControlZ) )
    {
        goto Finish;
    }

    // If this is a CarriageReturn, then look for a following LineFeed.
    if( ByteBuffer == CarriageReturn )
    {
        // Read the next byte.
        ByteBuffer = fgetc( AFile );
        
        // If the next byte isn't a line feed, put it back in the file
        // buffer.
        if( ByteBuffer != LineFeed )
        {
            ungetc( ByteBuffer, AFile );
            
            // Revert to the carriage return just read.
            ByteBuffer = CarriageReturn;
        }
    }
        
    // If an end-of-line sequence has been found, then finish up.
    if( (ByteBuffer == CarriageReturn) || (ByteBuffer == LineFeed) )
    {
        goto Finish;
    }

    // Accumulate the byte to the line buffer.
    *ABuffer++ = (s8) ByteBuffer;

    // Increment AByteCount to track the number of bytes added to the buffer.
    AByteCount++;
    
    // If the buffer is now full, then exit as with an end-of-file condition
    // by returning a -1. A buffer overflow of this kind may be indicative of
    // trying to read a binary file as if were a text file, or perhaps the
    // application simply needs to use a bigger line buffer to accomodate the 
    // type of file being read.
    if( AByteCount == BufferSize )
    {
        // Return -1 to signal that a line has not be read correctly.
        AByteCount = -1;
        
        // Stop reading from the file.
        goto Finish;
    }
    
    // Go read the next byte.
    goto ReadNextByte;

/////////   
Finish://
/////////   
 
    // If no bytes read at all before end-of-file, then return -1 instead of
    // the number of bytes read.
    if( (ByteBuffer == EOF) && (AByteCount == 0) ) 
    {
        // Set byte count to -1 to signal end-of-file.
        AByteCount = -1;
    }
    
    // If a valid line exist in the buffer, then append a zero to mark the end
    // of the text string.
    if( AByteCount != -1 )
    {
        *ABuffer = 0; 
    }
    
    // Return the number of bytes returned.
    return( AByteCount );
}
  
/*------------------------------------------------------------------------------
| ReadU64
|-------------------------------------------------------------------------------
|
| PURPOSE: To read a u64 integer from a file in LSB-first order.
|
| DESCRIPTION: 
|
| HISTORY: 
|    09Nov13 From ReadU32().
------------------------------------------------------------------------------*/
    // OUT: Number of bytes read: 8 on success, or 0 on error.
u32 //      
ReadU64( FILE* F, u64* Result )
{
    u8  b[8];
    u64 n;
    u32 BytesRead;
    
    // Read 8 bytes from the file.
    BytesRead = ReadBytes( F, b, 8 );

    // If the number of bytes read was not 8, then return 0.
    if( BytesRead != 8 )
    {
        return( 0 );
    }
    
    // Unpack the 64-bit integer from the 8 bytes read from the file.
    n =  Get_u64_LSB_to_MSB( (u8*) &b[0] );
     
    // Return the result.
    *Result = n;

    // Return the number of bytes read.
    return( BytesRead );
}

/*------------------------------------------------------------------------------
| ReportAvailableKeyBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To report to the user how many unused key bytes are available for 
|          encrypting messages in a list of one-time pad files.
|
| DESCRIPTION: Key bytes are only used once in one-time pad encryption, so this 
| routine is used to check how many key bytes remain available in a one-time 
| pad file.
|
| Opens each file in the list, performs any needed initialization, and prints 
| the number of available key bytes to standard output.
|
| The parameter KeyFileNames is the input to this routine.
|
| HISTORY: 
|    19Oct13 
|    24Dec13 Revised to support multiple key files.
|    24Feb14 Print all error and status messages even if verbose mode is not
|            abled since it is OK to print messages when listing the number of
|            unused bytes.
|    17Mar14 Made working buffers local to this routine and added memory 
|            clearing of buffers and variables used.
|    29Mar14 Added ability to specify key files indirectly using -KeyID or -ID 
|            parameters.
------------------------------------------------------------------------------*/
    // OUT: Result code to be passed back to the calling application, one of
    //      the values with the prefix 'RESULT_...'.
u32 //
ReportAvailableKeyBytes()
{
    ThatItem C;
    FILE* KeyFileHandle;
    s8*   KeyFileName;
    u64   KeyFileSize;
    u64   StartingAddress;
    u64   TotalUnusedBytes;
    u64   UnusedBytes;
    u8    KeyHashBuffer[KEY_FILE_HASH_SIZE]; // 8 bytes
    s8    KeyHashStringBuffer[KEY_FILE_HASH_STRING_BUFFER_SIZE]; // 17 bytes
    static OT7Context e;
    
    // Zero an OT7 context record to be filled in from the key map.
    ZeroBytes( (u8*) &e, sizeof(OT7Context) );
     
    // Locate the key files based on command line input as augmented by other 
    // information found in the 'key.map' file.
    IdentifyEncryptionKey( &e );
     
    // Start the total of unused bytes at 0.
    TotalUnusedBytes = 0;
    
    // If there are no key file names specified, then just return.
    if( KeyFileNames.IsSpecified == 0 )
    {
        // Print status message to prompt the user for key file names.
        printf( "Need key file name(s) to print the number of unused bytes.\n" );
        
        return( RESULT_OK );
    }
    
    // Refer to the first file name in the string list.
    ToFirstItem( KeyFileNames.Value, &C ); 
    
    // Report the available bytes for each file in the list.
    while( C.TheItem )    
    {
        // Refer to the file name string attached to the current Item record.
        KeyFileName = (s8*) C.TheItem->DataAddress;
        
        // Open the one-time pad key file.
        //
        // OUT: File handle, or 0 if an error occurred.
        KeyFileHandle = OpenKeyFile( KeyFileName );
 
        // If unable to open the one-time pad file, then return.
        if( KeyFileHandle == 0 )
        {
            // OpenKeyFile() has already handled printing any error messages and 
            // setting the result code to be returned when the application 
            // exits.
         
            // Try the next key file.
            goto TryNextKeyFile;
        }
    
        // Compute a hash string to identify the one-time pad key file based on
        // the content of the first 32 bytes in the file.
        //
        // OUT: RESULT_OK if successful, or some other status code if there was 
        //      an error.
        Result =
            ComputeKeyHash( 
                KeyFileName,
                    // File name of the one-time pad key file, a zero-terminated
                    // ASCII string.
                    //
                KeyFileHandle,
                    // File handle of a one-time pad key file, opened for 
                    // read-only or read/write access.
                    //
                KeyHashBuffer,
                    // OUT: Output buffer for the key file hash in binary form. The
                    //      size of the buffer is KEY_FILE_HASH_SIZE = 8 bytes.
                    //
                KeyHashStringBuffer );
                    // OUT: Output buffer used to hold the hash string. Must be 
                    // at least (KEY_FILE_HASH_SIZE*2) + 1 bytes.

        // If there was an error computing the file ID hash of the key file, 
        // then try the next key file if any.
        if( Result != RESULT_OK )
        {
            // The error message has already been printed by 
            // ComputeKeyHash().
            
            // Try the next key file.
            goto TryNextKeyFile;
        }
    
        // Look up the starting address of the key using the 'ot7.log' file.
        //            
        // OUT: Offset of the first unused key byte in the file.
        StartingAddress = 
            LookupOffsetOfFirstUnusedKeyByte( (s8*) &KeyHashStringBuffer[0] );
                                                        // A hash string that 
                                                        // identifies the 
                                                        // one-time pad key 
                                                        // file.
        // Get the size of the key file. 
        KeyFileSize = GetFileSize64( KeyFileHandle );
        
        // If there was an error determining the size of the key file, then 
        // print an error message and go try the next key file.
        if( KeyFileSize == MAX_VALUE_64BIT )
        {
            // Print error message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "ERROR: Can't set file position in file '%s'.\n", 
                         KeyFileName );
            }

            // Set the result code to be returned when the application exits.
            Result = RESULT_CANT_SEEK_IN_KEY_FILE;
     
            // Try the next key file.
            goto TryNextKeyFile;
        }
        
        // Calculate the number of unused bytes in the key file.
        UnusedBytes = KeyFileSize - StartingAddress;
          
        // Print the number of unused byte to standard output.
        printf( "Key file '%s' has %s unused bytes.\n", 
                KeyFileName,
                ConvertIntegerToString64(UnusedBytes) );
             
        // Add the number of unused bytes to the total.
        TotalUnusedBytes += UnusedBytes;

/////////////////
TryNextKeyFile://
/////////////////

        // If the file is open, then close it.
        if( KeyFileHandle )
        {
            fclose( KeyFileHandle );
            
            // Mark the file as closed.
            KeyFileHandle = 0;
        }
                 
        // Advance the item cursor to the next item in the list.           
        ToNextItem(&C);
    }
    
    // If the total is different than the last printed amount for a file,
    // then print the overall total.
    if( TotalUnusedBytes != UnusedBytes )
    {
        printf( "Total unused key bytes: %s\n", 
                 ConvertIntegerToString64(TotalUnusedBytes) );
    } 
    
//////////    
CleanUp://
//////////    
    
    // Clear working buffers used by this routine.       
    ZeroBytes( (u8*) &e, sizeof(OT7Context) );
    ZeroBytes( KeyHashBuffer, KEY_FILE_HASH_SIZE ); 
    ZeroBytes( (u8*) KeyHashStringBuffer, KEY_FILE_HASH_STRING_BUFFER_SIZE );
    ZeroBytes( (u8*) &C, sizeof( ThatItem ) );
    
    // Clear variables used by this routine.       
    KeyFileHandle = 0;
    KeyFileName = 0;
    KeyFileSize = 0;
    StartingAddress = 0;
    TotalUnusedBytes = 0;
    UnusedBytes = 0;
       
    // Return the result code.
    return( Result );
}

/*------------------------------------------------------------------------------
| ReverseString
|-------------------------------------------------------------------------------
|
| PURPOSE: To reverse the bytes in a string in place.
|
| DESCRIPTION:  
|
| HISTORY: 
|    08Mar97 Revised to use pointers for speed.
|    09Nov13 Revised comments.
-----------------------------------------------------------------------------*/
void
ReverseString( s8* A )
{
    s8  a, b;
    s8* B;
    
    // Locate the last character in the string.
    B = A;
    
    // Scan until B points to the zero-terminator byte.
    while( *B ) 
    {
        B++;
    }
    
    // Back up one byte to the first non-zero byte, or prior to the first
    // byte if it happens to be zero.
    B--;

    // While B follows A, swap high and low order bytes, moving to the center 
    // till they meet.
    while( A < B ) 
    {
        a = *A;
        b = *B;
    
        *A++ = b;
        *B-- = a;
    }
}

/*------------------------------------------------------------------------------
| SetFilePosition
|-------------------------------------------------------------------------------
|
| PURPOSE: To set file position to a certain byte offset from the beginning of 
|          the file.
|
| DESCRIPTION: Returns 0 on success, or -1 if there was an error.
|
| HISTORY:  
|    06Oct13 Revised comments.
|    09Nov13 Revised to support 64-bit file offsets.
------------------------------------------------------------------------------*/
    // OUT: Returns 0 on success, or -1 if there was an error.
s32 //
SetFilePosition( FILE* FileHandle, u64 ByteOffset )
{
    s32 Result;
    
    // Seek relative to the beginning of the file.
    Result = (s32) fseeko64( FileHandle, (s64) ByteOffset, SEEK_SET ); 
    
    // Return the result: 0 on success, or -1 if an error.
    return( Result );
}

/*------------------------------------------------------------------------------
| SetOffsetOfFirstUnusedKeyByte
|-------------------------------------------------------------------------------
|
| PURPOSE: To log the file offset of the first unused key byte in a key file.
|
| DESCRIPTION: A log file is maintained to keep track of how many key bytes 
| have been used in one-time pad key files. This file is named 'ot7.log' by 
| default, but a different name can also be specified on the command line. 
|
| Each line of the log file consists of an identifier for a key file followed 
| by a space and then a decimal number representing the offset in the file of
| the first unused key byte. 
|
| For example, here is a line from the log file:
|
|            2819ED98F3020672 24875
|                   /            \
|         KeyHash__/              \___Offset of first unused key byte
|
| The first 32 bytes of a one-time pad key file is reserved as the signature of 
| the file and not used for encryption. An 8-byte hash called KeyHash is 
| computed from this 32-byte signature, and it is that value which is stored in 
| the 'ot7.log' file. The 8-byte hash expands to 16 ASCII hex digits when 
| written to the log file.
|
| The KeyHash identifies key files by their content in a way that allows a
| linkage from a key file to an entry in the log file, but not back the other
| way from a log file to a key file unless the 32-byte signature of the key file 
| is known.
|
| HISTORY: 
|    26Jan14 From LookupOffsetOfFirstUnusedKeyByte().
------------------------------------------------------------------------------*/
    // OUT: Result code of RESULT_OK if successful, or an error code.
u32 //
SetOffsetOfFirstUnusedKeyByte( 
    s8* KeyHashString,
            // A hash string that identifies a one-time pad key file by its
            // contents. See ComputeKeyHash() for more.
            //
    u64 FirstUnusedByte )
            // Address of the first unused byte in the file identified by the
            // hash string.
 {
    Item* AnItem;
    s8* AString;
    ThatItem C;
    List* L;
    s8* S;
    u32 WriteResult;
    
    // Make a string with the key file hash and file offset in the line buffer.
    // For example,
    //
    //            2819ED98F3020672 24875
    //                   /            \
    //         KeyHash__/              \___Offset of first unused key byte
    //
    sprintf( 
        &TextLineBuffer[0], 
        "%s %s",
        KeyHashString,
        ConvertIntegerToString64( FirstUnusedByte ) );
     
    // Copy the string to its own dynamically allocated buffer.
    AString = DuplicateString( &TextLineBuffer[0] );

    // If unable to allocate the string buffer, then return with an
    // error code.
    if( AString == 0 )
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Out of memory.\n" );
        }

        return( RESULT_OUT_OF_MEMORY );
    }
    
    // Now we have the string ready to insert into the file.

    //--------------------------------------------------------------------------
 
    // If the log file hasn't been loaded into memory yet, then read it from the 
    // log file as a linked list of strings, one per line.  
    if( LogFileList.IsSpecified == 0 )
    {
        // Try to read the log file into a string list.
        L = ReadListOfTextLines( LogFileName.Value );
        
        // If able to read the contents of the log file, then assign the list
        // to the LogFileList parameter.
        if( L )
        {
            // Print a status message if in verbose mode.
            if( IsVerbose.Value )
            {
                printf( "Read log file '%s' with %d items.\n", 
                        LogFileName.Value,
                        L->ItemCount );
            }
            
            // If the LogFileList has a default value, then delete it.
            if( LogFileList.Value )
            {
                DeleteListOfDynamicData( LogFileList.Value );
            }
            
            // Assign the list just read to the LogFileList parameter.
            LogFileList.Value = L;
            
            // Mark the LogFileList parameter as having been specified.
            LogFileList.IsSpecified = 1;
        }
    }
      
    // Now have a list ready for insertion of the new string.
     
    //--------------------------------------------------------------------------
     
    // Look for a matching hash string in the log file list.
    
    // Refer to the first item in the log file list using item cursor 'C'.
    ToFirstItem( LogFileList.Value, &C );
     
    // Scan the list to the end or until a match is found.
    while( C.TheItem )    
    {
        // Scan the current text line for the hash string. Returns the address 
        // of the hash in the string, or 0 if not found.
        S = FindStringInString( 
                KeyHashString, 
                (s8*) C.TheItem->DataAddress );
    
        // If the hash was found in the current string, then replace the string
        // attached to the item with the new string made above.
        if( S )
        {
            // Deallocate the string buffer, filling it with zeros.
            DeleteString( (s8*) C.TheItem->DataAddress );
    
             // Link to the string buffer allocated above.
             C.TheItem->DataAddress = (u8*) AString;
             
             // Go write the list to the log file.
             goto WriteListToLogFile;
         }
         
        // Advance the item cursor to the next item in the list.           
        ToNextItem(&C);
    }
    
    //--------------------------------------------------------------------------
    
    // The hash was not found, so append the new string to the list.
        
    // Append the new string to the empty list.
    AnItem = InsertDataLastInList( LogFileList.Value, (u8*) AString );

    // If unable to allocate an Item record for the string, then delete string 
    // and exit.
    if( AnItem == 0 )
    {
        // Deallocate the string buffer, filling it with zeros.
        DeleteString( AString );
        
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Out of memory.\n" );
        }
          
        // Return the out of memory error code.
        return( RESULT_OUT_OF_MEMORY );
    }
    
/////////////////////
WriteListToLogFile://
/////////////////////

    // Write a backup copy of the log file first for safety.
    // OUT: RESULT_OK if OK, otherwise an error code.
    WriteResult  = 
        WriteListOfTextLines( 
            "ot7log.bak",
                    // File name, a zero-terminated ASCII string.
                    //
            LogFileList.Value );
                    // A list of strings to be written.

    // If able to write the backup copy of the log file, then print status.
    if( WriteResult == RESULT_OK )
    {
        // Print a status message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "Wrote backup log file 'ot7log.bak' with %d items.\n", 
                    LogFileList.Value->ItemCount );
        }
    }
    else // If unable to write the backup copy of the log file, then return 
         // with an error code.
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't write backup log file 'ot7log.bak'.\n" );
            
            printf( "Primary log file '%s' will not be updated.\n", 
                    LogFileName.Value );
        }

        // Exit, returning the result code.
        return( WriteResult );
    }
    
    // Write a the log file.
    // OUT: RESULT_OK if OK, otherwise an error code.
    WriteResult  = 
        WriteListOfTextLines( 
            LogFileName.Value,
                    // File name, a zero-terminated ASCII string.
                    //
            LogFileList.Value );
                    // A list of strings to be written.

    // If able to write the primary log file, then print status.
    if( WriteResult == RESULT_OK )
    {
        // Print a status message if in verbose mode.
        if( IsVerbose.Value )
        {
            printf( "Wrote primary log file '%s' with %d items.\n", 
                    LogFileName.Value,
                    LogFileList.Value->ItemCount );
        }
    }
    else // If unable to write the primary log file, then return 
         // with an error code.
    {
        // Print error message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "ERROR: Can't write log file '%s',\n", LogFileName.Value );
                    
            printf( "but was able to write backup log to 'ot7log.bak'.\n" );
                    
            printf( "You can manually recover the primary log file from 'ot7log.bak'.\n" );
        }

        // Exit, returning the result code.
        return( WriteResult );
    }
    
    //--------------------------------------------------------------------------
    
    // The log file and a backup copy have been written successfully.
    
    // Delete the backup copy of the log file.
    remove( "ot7log.bak" );
    
    // Print a status message if in verbose mode.
    if( IsVerbose.Value )
    {
        printf( "Backup log 'ot7log.bak' has been deleted.\n" );
    }
     
    // Successful, return RESULT_OK. Log file list will be deallocated later.
    return( RESULT_OK );
}

/*------------------------------------------------------------------------------
| SelectFillSize
|-------------------------------------------------------------------------------
|
| PURPOSE: To select the number of fill bytes to use in an OT7 record based on 
|          the size of the plain text. 
|
| DESCRIPTION: In order for the fill bytes to mask the size of the text in an
| encrypted message, the number of fill bytes must be roughly proportional to 
| the number of text bytes. Otherwise, as the size of the text increases, the 
| size of the whole encrypted message will tend to imply the size of the text. 
|
| The approach used here is to make the number of fill bytes a random value in
| the range from 0 to the number of text bytes. If your needs are such that 
| using that many fill bytes is too costly, then just edit this routine to 
| implement a different policy, or specify the number of fill bytes on the
| command line using the -f <# of bytes> option.
|
| The one-time pad file is used as the source of random numbers for this 
| function.
|
| HISTORY: 
|    05Oct13 
------------------------------------------------------------------------------*/
    // OUT: The number of fill bytes to use, or MAX_VALUE_64BIT if an error 
    //      occurred.
u64 //
SelectFillSize( 
    FILE* KeyFileHandle,
    u64   PlaintextSize )
{
    u64 FillByteCount;
    u64 RandomValue;
    u32 BytesRead;

    // Read a 64-bit random number from the one-time pad file.
    BytesRead = ReadU64( KeyFileHandle, &RandomValue );

    // If unable to read the random number, then return the error code.
    if( BytesRead != 8 )
    {
        return( MAX_VALUE_64BIT );
    }
 
    // Randomly generate the size of the Fill area based on the size of the
    // plain text. To avoid possible division by zero, add one to the plain 
    // text size.
    FillByteCount = RandomValue % (PlaintextSize+1);
 
    // Return the number of fill bytes to use.
    return( FillByteCount );
}
 
/*------------------------------------------------------------------------------
| Skein_Get64_LSB_First
|-------------------------------------------------------------------------------
|
| PURPOSE: To copy 64-bit integers stored in LSB-to-MSB order into an array of
|          64-bit integers. 
|
| DESCRIPTION: The byte ordering of the native CPU is used in the destination
| buffer, but the source buffer is always in LSB-to-MSB order.
|
| HISTORY:  
|    20Feb14 From Skein 1.3.
------------------------------------------------------------------------------*/
void    
Skein_Get64_LSB_First( u64* dst, u8* src, u32 WordCount )
{  
    // Copy the given number of 64-bit words, reordering bytes to native CPU
    // ordering from LSB-first ordering.
    while( WordCount-- )
    {
        // Copy one 64-bit word with reordering, and advance the destination
        // address by one word (8 bytes).
        *dst++ = Get_u64_LSB_to_MSB( src );
        
        // Advance the source address by 8 bytes.
        src += 8;
    }
}

/*------------------------------------------------------------------------------
| Skein_Put64_LSB_First
|-------------------------------------------------------------------------------
|
| PURPOSE: To copy bytes from 64-bit integers into a buffer in LSB-to-MSB order. 
|
| DESCRIPTION:  
|
| HISTORY:  
|    13Feb14 From Skein 1.3 reference implementation with minor edits.
------------------------------------------------------------------------------*/
void    
Skein_Put64_LSB_First( u8* dst, u64* src, u32 ByteCount )
{  
    u32 i;

    for( i = 0; i < ByteCount; i++ )
    {
        dst[i] = (u8) ( src[i>>3] >> (8*(i&7)) );
    }
}

/*------------------------------------------------------------------------------
| Skein1024_Final
|-------------------------------------------------------------------------------
|
| PURPOSE: To finalize a hash computation and output the result.
|
| DESCRIPTION: This is the third stage of the process of making a Skein1024
| hash. See also Skein1024_Init() and Skein1024_Update().
|
| HISTORY:  
|    13Feb14 From Skein 1.3 reference implementation with minor edits.
|    03May14 Simplified parameter logic of Skein_Start_New_Type() macro.
------------------------------------------------------------------------------*/
void
Skein1024_Final( Skein1024Context* ctx, u8* hashVal )
{
    u32 i, n, byteCnt;
    u64 X[SKEIN1024_STATE_WORDS];
     
    // tag as the final block.
    ctx->T[1] |= SKEIN_T1_FLAG_FINAL;                 
    
    // zero pad b[] if necessary.
    if( ctx->bCnt < SKEIN1024_BLOCK_BYTES )            
    {
        memset( &ctx->b[ctx->bCnt], 0, SKEIN1024_BLOCK_BYTES - ctx->bCnt );
    }
    
    // process the final block.
    Skein1024_Process_Block( ctx, ctx->b, 1, ctx->bCnt );  
    
    // now output the result 
    
    // total number of output bytes.
    byteCnt = (ctx->hashBitLen + 7) >> 3;            

    // Run Threefish in "counter mode" to generate output.
    
    // Zero out b[], so it can hold the counter.
    memset( ctx->b, 0, sizeof(ctx->b) );  
    
    // Keep a local copy of counter mode "key".
    memcpy( X, ctx->X, sizeof(X) );       

    for( i = 0; i*SKEIN1024_BLOCK_BYTES < byteCnt; i++ )
    {
        // build the counter block.
        Put_u64_LSB_to_MSB( (u64) i, (u8*) &ctx->b[0] );
        
        Skein_Start_New_Type( ctx, SKEIN_T1_BLK_TYPE_OUT_FINAL );
        
        // run "counter mode" 
        Skein1024_Process_Block( ctx, ctx->b, 1, sizeof(u64) ); 
        
        // number of output bytes left to go.
        n = byteCnt - i * SKEIN1024_BLOCK_BYTES;   
        
        if( n >= SKEIN1024_BLOCK_BYTES )
        {
            n  = SKEIN1024_BLOCK_BYTES;
        }
          
        // "output" the ctr mode bytes.
        Skein_Put64_LSB_First( hashVal+i*SKEIN1024_BLOCK_BYTES, ctx->X, n );   
         
        // Restore the counter mode key for next time.
        memcpy( ctx->X, X, sizeof(X) );   
    }
}

/*------------------------------------------------------------------------------
| Skein1024_Init
|-------------------------------------------------------------------------------
|
| PURPOSE: To initialize a Skein1024 context for making a hash value of a given
|          size.
|
| DESCRIPTION: Making a Skein1024 hash is a three-stage process. This routine
| is does the first part, followed by Skein1024_Update() and Skein1024_Final()
| to complete the production of a hash value.
|
| HISTORY:  
|    13Feb14 From Skein 1.3 reference implementation with minor edits.
|    28Feb14 Added zeroing the whole context record to begin with. Changed 
|            memset() calls to ZeroBytes().
|    03May14 Simplified parameter logic of Skein_Start_New_Type() macro.
------------------------------------------------------------------------------*/
void 
Skein1024_Init( Skein1024Context* ctx, u32 hashBitLen )
{
    // Config block.
    u64 w[SKEIN1024_STATE_WORDS];
    
    // Zero the whole hash context whole record to begin with.
    ZeroBytes( (u8*) ctx, sizeof(Skein1024Context) );
     
    // Build/process config block for hashing.
    
    // Save the output hash size, defined as a certain number of bits.
    ctx->hashBitLen = hashBitLen; 
    
    // Set tweaks: T0=0; T1=CFG | FINAL.
    Skein_Start_New_Type( ctx, SKEIN_T1_BLK_TYPE_CFG_FINAL );        

    // Zero fill the configuration block.
    ZeroBytes( (u8*) &w[0], sizeof(w) );
      
    // Set the schema, version.
    Put_u64_LSB_to_MSB( (u64) SKEIN_SCHEMA_VER, (u8*) &w[0] );
     
    // Hash result length in bits.
    Put_u64_LSB_to_MSB( (u64) hashBitLen, (u8*) &w[1] );
     
    // Use the value that means tree hashing is not being done.
    Put_u64_LSB_to_MSB( (u64) SKEIN_CFG_TREE_INFO_SEQUENTIAL, (u8*) &w[2] );

    // Zero the chaining variables.
    ZeroBytes( (u8*) &ctx->X[0], sizeof(ctx->X) );        
    
    // Compute the initial chaining values from config block.
    Skein1024_Process_Block( ctx, (u8*) w, 1, SKEIN_CFG_STR_LEN );

    // The chaining vars ctx->X are now initialized for the given hashBitLen.
    // Set up to process the data message portion of the hash (default).
    // Set tweaks: T0 = 0, T1 = MSG type, bCnt = 0.
    Skein_Start_New_Type( ctx, SKEIN_T1_BLK_TYPE_MSG );          
}

/*------------------------------------------------------------------------------
| Skein1024_Print
|-------------------------------------------------------------------------------
|
| PURPOSE: To print a Skein1024 hash context for debugging and validation.
|
| DESCRIPTION: This routine is only used for testing of the ot7 tool.
|
| HISTORY:  
|    03Mar14
------------------------------------------------------------------------------*/
void
Skein1024_Print( Skein1024Context* ctx )
{
    // Print all the fields in the given Skein1024Context record.
    
    printf( "hashBitLen = %u\n", ctx->hashBitLen );

    printf( "bCnt = %u\n", ctx->bCnt );

    printf( "T[] = '%s'\n",
            ConvertBytesToHexString( (u8*) &ctx->T[0], sizeof(ctx->T) ) );

    printf( "X[] = '%s'\n",
            ConvertBytesToHexString( (u8*) &ctx->X[0], SKEIN1024_BLOCK_BYTES ) );

    printf( "b[] = '%s'\n", 
            ConvertBytesToHexString( (u8*) &ctx->b[0], sizeof(ctx->b) ) );
}

/*------------------------------------------------------------------------------
| Skein1024_Process_Block
|-------------------------------------------------------------------------------
|
| PURPOSE: To perform the mixing operations involved in computing a Skein1024 
|          hash.
|
| DESCRIPTION: This is a common processing block used by several other routines.
| It processes one or more blocks of input data into a Skein1024 hash.
|
| HISTORY:  
|    13Feb14 From Skein 1.3 reference implementation with minor edits.
------------------------------------------------------------------------------*/
void 
Skein1024_Process_Block(
    Skein1024Context* ctx,
            // State and configuration information for a Skein1024 hash.
            // 
    u8* blkPtr,
            // Location of input data.
            //
    u32 blkCnt,
            // Number of blocks of input data to process.
            //
    u32 byteCntAdd )
            // Size of each input block in bytes. 
{ 
    u32 i,r;
    u64 ts[3];                        // key schedule: tweak.
    u64 ks[SKEIN1024_STATE_WORDS+1];  // key schedule: chaining vars 
    u64 X[SKEIN1024_STATE_WORDS];     // local copy of vars 
    u64 w[SKEIN1024_STATE_WORDS];     // local copy of input block

    while( blkCnt-- )
    {
        // This implementation only supports 2**64 input bytes.
        
        // Increase the processed length by the size in bytes of one input 
        // block.
        ctx->T[0] += byteCntAdd;    

        // precompute the key schedule for this block.
        ks[SKEIN1024_STATE_WORDS] = SKEIN_KS_PARITY;
        
        for( i = 0; i < SKEIN1024_STATE_WORDS; i++ )
        {
            ks[i] = ctx->X[i];
            
            // compute overall parity 
            ks[SKEIN1024_STATE_WORDS] ^= ctx->X[i];   
        }
        
        ts[0] = ctx->T[0];
        ts[1] = ctx->T[1];
        ts[2] = ts[0] ^ ts[1];
        
        // Get input block in little-endian format.
        Skein_Get64_LSB_First( w, blkPtr, SKEIN1024_STATE_WORDS ); 
        
        // Do the first full key injection.
        for (i=0;i < SKEIN1024_STATE_WORDS; i++)               
        {
            X[i]  = w[i] + ks[i];
        }
        
        X[SKEIN1024_STATE_WORDS-3] += ts[0];
        X[SKEIN1024_STATE_WORDS-2] += ts[1];

        // For 80 rounds: 10 x 8 rounds unrolled.
        for ( r=1; r <= SKEIN1024_ROUNDS_TOTAL/8; r++ )
        { 
            X[ 0] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_0_0); X[ 1] ^= X[ 0];
            X[ 2] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_0_1); X[ 3] ^= X[ 2];
            X[ 4] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_0_2); X[ 5] ^= X[ 4];
            X[ 6] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_0_3); X[ 7] ^= X[ 6];
            X[ 8] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_0_4); X[ 9] ^= X[ 8];
            X[10] += X[11]; X[11] = RotL_64(X[11],R_0_5); X[11] ^= X[10];
            X[12] += X[13]; X[13] = RotL_64(X[13],R_0_6); X[13] ^= X[12];
            X[14] += X[15]; X[15] = RotL_64(X[15],R_0_7); X[15] ^= X[14];     

            X[ 0] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_1_0); X[ 9] ^= X[ 0];
            X[ 2] += X[13]; X[13] = RotL_64(X[13],R_1_1); X[13] ^= X[ 2];
            X[ 6] += X[11]; X[11] = RotL_64(X[11],R_1_2); X[11] ^= X[ 6];
            X[ 4] += X[15]; X[15] = RotL_64(X[15],R_1_3); X[15] ^= X[ 4];
            X[10] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_1_4); X[ 7] ^= X[10];
            X[12] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_1_5); X[ 3] ^= X[12];
            X[14] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_1_6); X[ 5] ^= X[14];
            X[ 8] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_1_7); X[ 1] ^= X[ 8]; 

            X[ 0] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_2_0); X[ 7] ^= X[ 0];
            X[ 2] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_2_1); X[ 5] ^= X[ 2];
            X[ 4] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_2_2); X[ 3] ^= X[ 4];
            X[ 6] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_2_3); X[ 1] ^= X[ 6];
            X[12] += X[15]; X[15] = RotL_64(X[15],R_2_4); X[15] ^= X[12];
            X[14] += X[13]; X[13] = RotL_64(X[13],R_2_5); X[13] ^= X[14];
            X[ 8] += X[11]; X[11] = RotL_64(X[11],R_2_6); X[11] ^= X[ 8];
            X[10] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_2_7); X[ 9] ^= X[10]; 
                                                                            
            X[ 0] += X[15]; X[15] = RotL_64(X[15],R_3_0); X[15] ^= X[ 0];
            X[ 2] += X[11]; X[11] = RotL_64(X[11],R_3_1); X[11] ^= X[ 2];
            X[ 6] += X[13]; X[13] = RotL_64(X[13],R_3_2); X[13] ^= X[ 6];
            X[ 4] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_3_3); X[ 9] ^= X[ 4];
            X[14] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_3_4); X[ 1] ^= X[14];
            X[ 8] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_3_5); X[ 5] ^= X[ 8];
            X[10] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_3_6); X[ 3] ^= X[10];
            X[12] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_3_7); X[ 7] ^= X[12];  
            
            InjectKey(2*r-1);

            X[ 0] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_4_0); X[ 1] ^= X[ 0];
            X[ 2] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_4_1); X[ 3] ^= X[ 2];
            X[ 4] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_4_2); X[ 5] ^= X[ 4];
            X[ 6] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_4_3); X[ 7] ^= X[ 6];
            X[ 8] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_4_4); X[ 9] ^= X[ 8];
            X[10] += X[11]; X[11] = RotL_64(X[11],R_4_5); X[11] ^= X[10];
            X[12] += X[13]; X[13] = RotL_64(X[13],R_4_6); X[13] ^= X[12];
            X[14] += X[15]; X[15] = RotL_64(X[15],R_4_7); X[15] ^= X[14]; 

            X[ 0] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_5_0); X[ 9] ^= X[ 0];
            X[ 2] += X[13]; X[13] = RotL_64(X[13],R_5_1); X[13] ^= X[ 2];
            X[ 6] += X[11]; X[11] = RotL_64(X[11],R_5_2); X[11] ^= X[ 6];
            X[ 4] += X[15]; X[15] = RotL_64(X[15],R_5_3); X[15] ^= X[ 4];
            X[10] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_5_4); X[ 7] ^= X[10];
            X[12] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_5_5); X[ 3] ^= X[12];
            X[14] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_5_6); X[ 5] ^= X[14];
            X[ 8] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_5_7); X[ 1] ^= X[ 8]; 

            X[ 0] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_6_0); X[ 7] ^= X[ 0];
            X[ 2] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_6_1); X[ 5] ^= X[ 2];
            X[ 4] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_6_2); X[ 3] ^= X[ 4];
            X[ 6] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_6_3); X[ 1] ^= X[ 6];
            X[12] += X[15]; X[15] = RotL_64(X[15],R_6_4); X[15] ^= X[12];
            X[14] += X[13]; X[13] = RotL_64(X[13],R_6_5); X[13] ^= X[14];
            X[ 8] += X[11]; X[11] = RotL_64(X[11],R_6_6); X[11] ^= X[ 8];
            X[10] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_6_7); X[ 9] ^= X[10]; 
                                                                            
            X[ 0] += X[15]; X[15] = RotL_64(X[15],R_7_0); X[15] ^= X[ 0];
            X[ 2] += X[11]; X[11] = RotL_64(X[11],R_7_1); X[11] ^= X[ 2];
            X[ 6] += X[13]; X[13] = RotL_64(X[13],R_7_2); X[13] ^= X[ 6];
            X[ 4] += X[ 9]; X[ 9] = RotL_64(X[ 9],R_7_3); X[ 9] ^= X[ 4];
            X[14] += X[ 1]; X[ 1] = RotL_64(X[ 1],R_7_4); X[ 1] ^= X[14];
            X[ 8] += X[ 5]; X[ 5] = RotL_64(X[ 5],R_7_5); X[ 5] ^= X[ 8];
            X[10] += X[ 3]; X[ 3] = RotL_64(X[ 3],R_7_6); X[ 3] ^= X[10];
            X[12] += X[ 7]; X[ 7] = RotL_64(X[ 7],R_7_7); X[ 7] ^= X[12];
             
            InjectKey(2*r);
        }
        
        // Do the final "feedforward" xor, update context chaining vars.
        for( i=0; i < SKEIN1024_STATE_WORDS; i++ )
        {
            ctx->X[i] = X[i] ^ w[i];
        }
        
        // Clear the start bit.
		ctx->T[1] &= ~SKEIN_T1_FLAG_FIRST;
		
        blkPtr += SKEIN1024_BLOCK_BYTES;
    } 
}

/*------------------------------------------------------------------------------
| Skein1024_Test
|-------------------------------------------------------------------------------
|
| PURPOSE: To test the Skein hash routines to make sure they conform to the
|          Skein standard.
|
| DESCRIPTION: This routine generates 1024-bit hashs using the Skein hash 
| function and then compares them to known results. The overall result is a 
| pass/fail code.
|
| Run this routine when porting OT7 to a new compiler to verify that the hash
| functions are working according to the Skein reference document "The Skein 
| Hash Function Family, Version 1.3 - 1 Oct 2010" (skein1.3.pdf). 
|
| HISTORY: 
|    30Nov14
------------------------------------------------------------------------------*/
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.  
u32 //
Skein1024_Test()
{
    u32 result;
     
    // Run the first of three hash test cases. 
    //
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.  
    result =
        Skein1024_TestCase( 
            (u8*) &Skein_1024_1024_Test_Vector_1_Message_Data, 
            (u32) sizeof( Skein_1024_1024_Test_Vector_1_Message_Data ), 
            (u8*) &Skein_1024_1024_Test_Vector_1_Result );

    // Return if the test case failed.
    if( result )
    {
        return( result );
    }    
 
    //--------------------------------------------------------------------------

    // Run the second hash test case. 
    //
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.  
    result =
        Skein1024_TestCase( 
            (u8*) &Skein_1024_1024_Test_Vector_2_Message_Data, 
            (u32) sizeof( Skein_1024_1024_Test_Vector_2_Message_Data ), 
            (u8*) &Skein_1024_1024_Test_Vector_2_Result );

    // Return if the test case failed.
    if( result )
    {
        return( result );
    }    
 
    //--------------------------------------------------------------------------

    // Run the third hash test case. 
    //
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.  
    result =
        Skein1024_TestCase( 
            (u8*) &Skein_1024_1024_Test_Vector_3_Message_Data, 
            (u32) sizeof( Skein_1024_1024_Test_Vector_3_Message_Data ), 
            (u8*) &Skein_1024_1024_Test_Vector_3_Result );

    // Return the result of the last test case.
    return( result );
}    

/*------------------------------------------------------------------------------
| Skein1024_TestCase
|-------------------------------------------------------------------------------
|
| PURPOSE: To test the 1024-bit Skein hash algorithm using reference data.
|
| DESCRIPTION: This routine generates a 1024-bit hash using the Skein hash 
| function and then compares it to a known result. The result is a pass/fail
| code.
|
| Run this routine when porting OT7 to a new compiler to verify that the hash
| function is working according to the reference implementation defined in the
| Skein reference document "The Skein Hash Function Family, Version 1.3 - 
| 1 Oct 2010" (skein1.3.pdf). See Appendix C for test vector data that can be
| used with this routine.  
|
| HISTORY: 
|    30Nov14 From ComputeKeyIDHash128bit().
------------------------------------------------------------------------------*/
    // OUT: Result code equal to RESULT_OK (0) if no error, otherwise an error 
    //      code.  
u32 //
Skein1024_TestCase( u8* MessageData, u32 MessageSize, u8* ExpectedResult )
{
    u32 i;
    static u8 Hash1024Buffer[128]; 
                // Computed 1024-bit hash buffer. 1024-bits is 128 bytes.
                //
    static Skein1024Context HashContext;
                // Static buffers are used in this routine to avoid taking up 
                // too much stack space.
   
    // Initialize the hash context for producing a 1024-bit hash.
    Skein1024_Init( &HashContext, 1024 );
    
    // At this point the chaining variables in the hash context should match
    // those published on page 72, section B.13 Skein-1024-124.
    
    // Compare each of the chaining variables to the published values.
    for( i = 0; i < SKEIN1024_STATE_WORDS; i++ )
    {
        // If any of the chaining variables doesn't match the standard, then
        // return an error code.
        if( HashContext.X[i] != Skein_1024_1024_Initial_Chaining_Values[i] )
        {
            // Print status message if verbose output is enabled.
            if( IsVerbose.Value )
            {
                printf( "FAIL: Hash function failed initialization test.\n" );
            }

            return( RESULT_SKEIN_TEST_INITIALIZATION_FAILED );
        }
    }
    
    // Feed the message data into the hash context.
    Skein1024_Update( &HashContext, MessageData, MessageSize );

    // Compute the final 1024-bit hash value, putting it into Hash1024Buffer.
    Skein1024_Final( &HashContext, Hash1024Buffer );
    
    // If the computed hash matches the expected hash value, then return
    // RESULT_OK (0).
    if( IsMatchingBytes( (u8*) &Hash1024Buffer, ExpectedResult, 128 ) )
    {
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "PASS: Hash function test case produced expected results.\n" );
            printf( "Final values in hash context:\n" );
            Skein1024_Print( &HashContext );
            printf( "\n" );
        }

        return( RESULT_OK );
    }
    else // Otherwise, return an error code.
    {
        // Print status message if verbose output is enabled.
        if( IsVerbose.Value )
        {
            printf( "FAIL: Hash function test case produce unexpected results.\n" );
            printf( "Final values in hash context:\n" );
            Skein1024_Print( &HashContext );
            printf( "\n" );
        }

        return( RESULT_SKEIN_TEST_FINAL_RESULT_IS_INVALID );
    }
}

/*------------------------------------------------------------------------------
| Skein1024_Update
|-------------------------------------------------------------------------------
|
| PURPOSE: To update a Skein1024 hash to include additional message data.
|
| DESCRIPTION: After initializing a Skein1024 context for a certain hash size
| with Skein1024_Init(), this routine is used to process a certain amount input 
| data.
|
| This routine can be called repeatedly until all of the message data has been
| processed.
|
| To produce the final hash value, call Skein1024_Final().
|
| HISTORY:  
|    13Feb14 From Skein 1.3 reference implementation with minor edits.
------------------------------------------------------------------------------*/
void
Skein1024_Update( Skein1024Context *ctx, u8* msg, u32 msgByteCnt )
{
    u32 n;

    // Process full blocks, if any.
    if( msgByteCnt + ctx->bCnt > SKEIN1024_BLOCK_BYTES )
    {
        // Finish up any buffered message data.
        if( ctx->bCnt )                              
        {
            // # bytes free in buffer b[].
            n = SKEIN1024_BLOCK_BYTES - ctx->bCnt;  

            if( n )
            {
                memcpy( &ctx->b[ctx->bCnt], msg, n );
                
                msgByteCnt -= n;
                msg        += n;
                ctx->bCnt  += n;
            }
            
            Skein1024_Process_Block( ctx, ctx->b, 1, SKEIN1024_BLOCK_BYTES );
            
            ctx->bCnt = 0;
        }
        
        // Now process any remaining full blocks, directly from input message 
        // data.
        if( msgByteCnt > SKEIN1024_BLOCK_BYTES )
        {
            // Number of full blocks to process.
            n = (msgByteCnt-1) / SKEIN1024_BLOCK_BYTES;   
            
            Skein1024_Process_Block( ctx, msg, n, SKEIN1024_BLOCK_BYTES );
            
            msgByteCnt -= n * SKEIN1024_BLOCK_BYTES;
            msg        += n * SKEIN1024_BLOCK_BYTES;
        }
    }

    // Copy any remaining source message data bytes into b[].
    if( msgByteCnt )
    {
        memcpy( &ctx->b[ctx->bCnt], msg, msgByteCnt );
        
        ctx->bCnt += msgByteCnt;
    }
}
  
/*------------------------------------------------------------------------------
| SkipWhiteSpace
|-------------------------------------------------------------------------------
|
| PURPOSE: To advance a parsing cursor past white space characters in a 
|          zero-terminated string.
|
| DESCRIPTION: White space characters are any of the following:
|
|              spaces, tabs, carriage returns, line feeds
| HISTORY: 
|    26Oct13
|    24Nov13 Added end-of-buffer to avoid scanning into other structures.
------------------------------------------------------------------------------*/
void
SkipWhiteSpace( 
    s8** Here,
          // IN/OUT: Address of the address of the current character.
          //
    s8*  AfterBuffer )
          // Address of the first byte after the buffer, a limit on how far 
          // forward scanning can go.
{
    s8  c;
    s8* Cursor;
    
    // Refer to the first character in the string using variable Cursor.
    Cursor = *Here;

//////////////
BoundsCheck://
//////////////
     
    // If the current byte is inside the buffer, then test if it is whitespace.
    if( Cursor < AfterBuffer )
    {
        // Get a character.
        c = *Cursor;
        
        // If it is whitespace, then advance to the next character and repeat 
        // the process
        if( IsWhiteSpace( c ) )  
        {
            // Refer to the next byte in the buffer as the current byte.
            Cursor++;
            
            // Go check to see if still in the buffer.
            goto BoundsCheck;
        }
    }
    
    // Update the parsing cursor to point to the first non-whitespace character
    // or at the string terminator, which ever comes first.
    *Here = Cursor;
}

/*------------------------------------------------------------------------------
| SkipWhiteSpaceBackward
|-------------------------------------------------------------------------------
|
| PURPOSE: To move a parsing cursor backward past white space characters.
|
| DESCRIPTION: White space characters are any of the following:
|
|           spaces, tabs, carriage returns, line feeds
| HISTORY: 
|    25Aug01 From SkipWhiteSpace().
------------------------------------------------------------------------------*/
void
SkipWhiteSpaceBackward( 
    s8** Here,
          // IN/OUT: Address of the address of the current character.
          //
    s8*  BeforeBuffer )
          // Address of the first byte before the buffer, a limit on how far 
          // backward scanning can go.
{
    s8  c;
    s8* Cursor;
    
    // Refer to the starting byte address.
    Cursor = *Here;

//////////////
BoundsCheck://
//////////////
     
    // If the current byte is inside the buffer, then test if it is whitespace.
    if( Cursor > BeforeBuffer )
    {
        // Get the current byte.
        c = *Cursor;
        
        // If the current byte is whitespace, then step back one byte and
        // repeat the process.
        if( IsWhiteSpace( c ) )  
        {
            // Refer to the prior byte in the buffer as the current byte.
            Cursor--;
            
            // Go check to see if still in the buffer.
            goto BoundsCheck;
        }
    }
    
    // Update the parsing cursor to point to a non-whitespace character or at
    // the byte prior to the buffer, which ever comes first.
    *Here = Cursor;
}

/*------------------------------------------------------------------------------
| StripCommentsInStringList
|-------------------------------------------------------------------------------
|
| PURPOSE: To strip out all comments from strings in a list.
|
| DESCRIPTION: Cmments begin with the characters '//' and continue to the end of
| the string.
|
| HISTORY: 
|    24Nov13 From StripTrailingWhiteSpaceInStringList().
|    27Nov13 Revised to use FindStringInString().
|    01Feb14 Revised to remove escape character sequence unrecognized by the
|            gcc compiler. Removed extra indirection of specialized string list
|            structure.
|    28Feb14 Removed unused DataSize field from Item record.
------------------------------------------------------------------------------*/
void
StripCommentsInStringList( List* L ) // A list of strings.
{
    s8* AtComment;
    ThatItem C;
    u32 CharCount;
    s8  CommentSequence[3];
    
    // Make the comment string sequence to search for.
    CommentSequence[0] = '/';
    CommentSequence[1] = '/';
    CommentSequence[2] = 0;
      
    // Refer to the first string in the list.
    ToFirstItem( L, &C );
    
    // For each string in the list.
    while( C.TheItem )
    {
        // If the current string contains characters, then trim any comment
        // off the end of the line.
        if( C.TheItem->DataAddress )
        {
            // Get the string count.
            CharCount = CountString( (s8*) C.TheItem->DataAddress );

            // If there are at least two characters in the string, then look
            // for a comment marker '//'.
            if( CharCount >= 2 )
            {
                // Look through the current line for a // comment. This 
                // routine only works with zero-terminated strings.
                AtComment = 
                    FindStringInString( 
                        (s8*) &CommentSequence[0], 
                        (s8*) C.TheItem->DataAddress );

                // If a comment was found, then trim the string to remove it.
                if( AtComment )
                {
                    // Fill all the bytes between the comment and the end of
                    // the string with zero bytes.
                    ZeroFillString( AtComment );
                }
            }
        }
        
        // Advance to the next string in the list.
        ToNextItem(&C);
    }
}

/*------------------------------------------------------------------------------
| StripLeadingWhiteSpaceInStringList
|-------------------------------------------------------------------------------
|
| PURPOSE: To strip "white space" characters (defined below) from the start of 
|          each string in a list.
|
| DESCRIPTION: White space characters are any of the following:
|
|                   spaces, tabs, carriage returns, line feeds
| HISTORY: 
|    12Aug01 
|    19Aug01 Added SizeOfString().
|    25Aug01 Revised to support counted strings.
|    24Nov13 Added buffer limit check to scanner routine and minor edits to
|            improve clarity.
|    01Feb14 Revised to remove specialized string list structure. Use general
|            purpose list traversal instead.
|    28Feb14 Removed Item field DataSize.
------------------------------------------------------------------------------*/
void
StripLeadingWhiteSpaceInStringList( List* L ) // L is a list of strings.
{
    ThatItem C;
    u32      CharCount;
    s8*      Here;
    u32      NewStringSize;
    u32      WhiteCount;
    
    // Refer to the first string in the list.
    ToFirstItem( L, &C );
    
    // For each string in the list.
    while( C.TheItem )
    {
        // If the current string contains characters, then trim any whitespace
        // off the beginning of the string.
        if( C.TheItem->DataAddress )
        {
            // Refer to the first character of the string, making a separate 
            // character cursor for scanning.
            Here = (s8*) C.TheItem->DataAddress;
                    
            // Count the number of characters in the string, not including the
            // zero at the end.
            CharCount = CountString( Here );
            
            // Scan to the first non-white character in the string.
            SkipWhiteSpace( 
                &Here,
                      // IN/OUT: Address of the address of the current 
                      // character.
                      //
                Here + CharCount );
                      // Address of the first byte after the buffer, a limit on 
                      // how far forward scanning can go.
             
            // Calculate the number of whitespace chars found.
            WhiteCount = Here - (s8*) C.TheItem->DataAddress;
            
            // If white chars have been found, then remove them.
            if( WhiteCount )
            {
                // Calculate the size of the string after removing the leading
                // whitespace characters.
                NewStringSize = CharCount - WhiteCount;
                 
                // If the non-white characters remain, copy them to the 
                // beginning of the string. 
                if( NewStringSize )
                {
                    // Copy the non-white characters to beginning of the 
                    // string.
                    CopyBytes( 
                        (u8*) Here,            
                                // Source address.
                                //
                        C.TheItem->DataAddress,     
                                // Destination address.
                                //
                        NewStringSize ); 
                                // Byte count.  
                }   
 
                // Update the string's zero-terminator, zero filling the
                // remainder of the string.
                ZeroFillString( (s8*) &C.TheItem->DataAddress[NewStringSize] );
            }
        }
              
        // Advance to the next string in the list.
        ToNextItem(&C);
    }
}
 
/*------------------------------------------------------------------------------
| StripTrailingWhiteSpaceInStringList
|-------------------------------------------------------------------------------
|
| PURPOSE: To strip "white space" characters (defined below) from the end of 
|          each string in a list.
|
| DESCRIPTION: White space characters are any of the following:
|
|           spaces, tabs, carriage returns, line feeds
|
| HISTORY: 
|    12Aug01 
|    19Aug01 Added SizeOfString().
|    25Aug01 Revised to support counted strings.
|    21Nov13 Handled not stopping at the beginning of the string when scanning
|            backward for first non-white character.
|    01Feb14 Revised to remove specialized string list structure. Use general
|            purpose list traversal instead.
|    28Feb14 Removed unused DataSize field from Item record and code from this
|            routine.
------------------------------------------------------------------------------*/
void
StripTrailingWhiteSpaceInStringList( List* L ) // A list of strings.
{
    ThatItem C;
    s8*      Here;
    s8*      Last;
    u32      CharCount;
    u32      NewStringSize;
    u32      WhiteCount;
    
    // Refer to the first string in the list.
    ToFirstItem( L, &C );
    
    // For each string in the list.
    while( C.TheItem )
    {
        // If the current string contains characters, then trim any whitespace
        // off the end of the string.
        if( C.TheItem->DataAddress )
        {
            // Count the number of characters in the string, not including the
            // zero at the end.
            CharCount = CountString( (s8*) C.TheItem->DataAddress );

            // If there are characters in the string, then look for trailing
            // whitespace.
            if( CharCount )
            {
                // Refer to the last character of the string.
                Last = (s8*) C.TheItem->DataAddress + CharCount - 1;
                
                // Make a separate character cursor for scanning.
                Here = Last;
                 
                // Move a parsing cursor backward past white space characters.
                SkipWhiteSpaceBackward( 
                    &Here,
                          // IN/OUT: Address of the address of the current 
                          // character.
                          //
                    ((s8*) C.TheItem->DataAddress) - 1 );
                          // Address of the first byte before the buffer, a 
                          // limit on how far backward scanning can go.
                 
                // Calculate the number of whitespace chars found.
                WhiteCount = Last - Here;
                
                // If white chars have been found, then deduct them from the 
                // string length.
                if( WhiteCount )
                {
                    // Calculate the size of the string after removing the 
                    // trailing whitespace characters.
                    NewStringSize = CharCount - WhiteCount;
                       
                       // Update the string's zero-terminator, zero filling the
                    // remainder of the string.
                    ZeroFillString( 
                        (s8*) &C.TheItem->DataAddress[NewStringSize] );
                }
            }
        }
              
        // Advance to the next string in the list.
        ToNextItem(&C);
    }
}

/*------------------------------------------------------------------------------
| ToFirstItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To set an item cursor to refer to the first item in a list.
|
| DESCRIPTION: This routine initializes an item cursor to hold the traversal
| context used when moving from one item to the next in a list.
|
| EXAMPLE:  
|  
|          ThatItem C;
|
|          ToFirstItem( L, &C );
|
|          while(C.TheItem)
|          {
|               ConvertStringToUpperCase( (s8*) C.TheItem->DataAddress );
|
|               ToNextItem(&C);
|          }
|
| HISTORY: 
|    04Jan89
|    06Jan02 Revised to use ThatItem from ToFirstChar().
------------------------------------------------------------------------------*/
void
ToFirstItem(    
    List*     L,
                // A list.
                //
    ThatItem* C ) 
                // The item cursor to hold the traversal context.  
{
    // Refer to the first item in the list.
    C->TheItem = L->FirstItem;
    
    // Refer to the list.
    C->TheList = L;
}

/*------------------------------------------------------------------------------
| ToNextItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To set the current item to be the next item in the current list.
|
| DESCRIPTION: This routine updates TheItem field of an item cursor to refer to 
| the next item in the list. This is a list traversal operation.
|
| This routine assumes that C->TheItem refers to a valid Item record.
|
| EXAMPLE:  
|  
|          ThatItem C;
|
|          ToFirstItem( L, &C );
|
|          while( C.TheItem )
|          {
|               ConvertStringToUpperCase( (s8*) C.TheItem->DataAddress );
|
|               ToNextItem( &C );
|          }
|
| HISTORY: 
|    04Jan89
|    06Jan02 Revised to use ThatItem.
------------------------------------------------------------------------------*/
void
ToNextItem( ThatItem* C ) 
                      // An item cursor which holds the traversal context.  
{
    // Update the current item address, stepping to the next item in the list.
    C->TheItem = C->TheItem->NextItem;
}
 
/*------------------------------------------------------------------------------
| ToPriorItem
|-------------------------------------------------------------------------------
|
| PURPOSE: To set the current item to be the prior item in the current list.
|
| DESCRIPTION: This routine updates TheItem field of an item cursor to refer to 
| the prior item in the list. This is a list traversal operation.
|
| This routine assumes that C->TheItem refers to a valid Item record.
|
| EXAMPLE:  
|  
|          ThatItem C;
|
|          ToLastItem( L, &C );
|
|          while( C.TheItem )
|          {
|               ConvertStringToUpperCase( (s8*) C.TheItem->DataAddress );
|
|               ToPriorItem( &C );
|          }
|
| HISTORY: 
|    04Jan89
|    06Jan02 Revised to use ThatItem.
------------------------------------------------------------------------------*/
void
ToPriorItem( ThatItem* C ) 
                      // An item cursor which holds the traversal context.  
{
    // Update the current item address, stepping to the previous item in the 
    // list.
    C->TheItem = C->TheItem->PriorItem;
}

/*------------------------------------------------------------------------------
| WriteByte
|-------------------------------------------------------------------------------
|
| PURPOSE: To write a byte to a file.
|
| DESCRIPTION: Returns the number of bytes actually written.
|
| EXAMPLE: Write the byte 'a' to an open file at the current file position.
|
|             NumberWritten = WriteByte( FileHandle, 'a' );
| 
| On return, NumberWritten will be 1 unless there is an error.
|
| HISTORY:  
|    19Oct13 Revised comments.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes written: should be 1 unless there was an error.
u32 //
WriteByte( FILE* FileHandle, u8 AByte )
{
    u32 NumberWritten;
      
    // Write the byte to the file at the current file position, returning the
    // number of bytes written.
    NumberWritten = WriteBytes( FileHandle, &AByte, 1 );

    // Return the number of bytes written.
    return( NumberWritten );
}

/*------------------------------------------------------------------------------
| WriteBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To write bytes from a buffer to a file.
|
| DESCRIPTION: Returns number of bytes written.
|
| EXAMPLE: Given an open file is open and a properly positioned file pointer,
| write 15 bytes to a file from buffer ABuffer.
|
|          NumberWritten = WriteBytes( FileHandle, ABuffer, 15 );
|
| HISTORY: 
|    19Oct13 Revised comments.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes written.
u32 //
WriteBytes( FILE* FileHandle,
                    // Handle of an open file.
                    //
            u8* BufferAddress,
                    // Buffer with data to be written to the file.
                    //
            u32 AByteCount )
                    // Number of bytes to write.
{
    u32 NumberWritten;

    // Start with no bytes written.
    NumberWritten = 0;
    
    // If a file handle is given and the number of bytes to be written is 
    // non-zero.
    if( FileHandle && AByteCount )
    {    
        // Write the bytes to the file returning the number actually written.
        NumberWritten = (u32) 
            fwrite( BufferAddress,
                    1,
                    AByteCount,
                    FileHandle );
    }
    
    // Return the number of bytes written.
    return( NumberWritten );
}

/*------------------------------------------------------------------------------
| WriteBytesX
|-------------------------------------------------------------------------------
|
| PURPOSE: To write a bytes to a file in either binary or base64 format.
|
| DESCRIPTION: Returns number of bytes written.
|
| EXAMPLE: Given an open file is open and a properly positioned file pointer,
| write 15 bytes to a file from buffer ABuffer.
|
|          NumberWritten = WriteBytesX( FileHandle, ABuffer, 15 );
|
| HISTORY: 
|    26Oct13
------------------------------------------------------------------------------*/
    // OUT: Number of bytes written.
u32 //
WriteBytesX( FILEX* F,
                    // Extended file handle of an open file.
                    //
             u8* BufferAddress,
                    // Buffer with data to be written to the file.
                    //
             u32 AByteCount )
                    // Number of bytes to write.
{
    u32 i;
    u32 NumberWritten;

    // Start with no bytes written.
    NumberWritten = 0;
    
    // Write the bytes in the form specified by the file format.
    switch( F->FileFormat )
    {
        case OT7_FILE_FORMAT_BINARY:
        {
            // If a file handle is given and the number of bytes to be 
            // written is non-zero, then write the bytes.
            if( F->FileHandle && AByteCount )
            {    
                // Write the bytes to the file returning the number actually 
                // written.
                NumberWritten = (u32) 
                    fwrite( BufferAddress,
                            1,
                            AByteCount,
                            F->FileHandle );
                            
                // Advance the file pointer by the number of bytes written.
                F->FilePositionInBytes += (u64) NumberWritten;
            }
         
            // Go to the exit.
            break;
        } 
        
        //----------------------------------------------------------------------
    
        // If writing in base64 format, then translate and write ASCII
        // characters instead of binary.
        case OT7_FILE_FORMAT_BASE64:
        {
            // Write each of the bytes in the buffer up to the given limit.
            for( i = 0; i < AByteCount; i++ )
            {
                // If the byte was written successfully, then increment the
                // number of bytes written.
                if( WriteByteX( F, BufferAddress[i] ) )
                {
                    NumberWritten++;
                } 
                else // Unable to write the byte.
                {
                    // Skip the rest of the buffer and go to the exit.
                    goto Exit;
                }
            }
        }
    }
    
///////
Exit://
///////
        
    // Return the number of bytes written.
    return( NumberWritten );
}
 
/*------------------------------------------------------------------------------
| WriteByteX
|-------------------------------------------------------------------------------
|
| PURPOSE: To write a byte to a file in either binary or base64 format.
|
| DESCRIPTION: Returns the number of input bytes written. Some expansion of
| input bytes to the output format may result in more actual bytes being 
| written to the file.
|
| EXAMPLE: Write the byte 0xF3 to an open file at the current file position.
|
|                NumberWritten = WriteByteX( AFileHandle, 0xF3 );
| 
| On return, NumberWritten will be 1 unless there is an error.
|
| HISTORY:  
|    20Oct13 Revised comments.
------------------------------------------------------------------------------*/
    // OUT: Number of bytes written: either 1 or 0 if there was an error.
u32 //
WriteByteX( FILEX* F, u8 ByteToWrite )
{
    u8  i;
    u8  Letter;
    u32 WordIndex;
    u32 NumberWritten;
    
    // Start with no bytes written.
    NumberWritten = 0;
      
    // Write the byte in the form specified by the file format.
    switch( F->FileFormat )
    {
        // If writing in binary format, then call the ordinary byte write 
        // routine.
        case OT7_FILE_FORMAT_BINARY:
        {
            // Write the byte to the file at the current file position, 
            // returning the number of bytes written.
            NumberWritten = WriteByte( F->FileHandle, ByteToWrite );
            
            // Advance the file pointer by the number of bytes written.
            F->FilePositionInBytes += (u64) NumberWritten;
        
            // Go to the exit.
            break;
        } 
        
        //----------------------------------------------------------------------
    
        // If writing in base64 format, then translate and write ASCII
        // characters instead of binary.
        case OT7_FILE_FORMAT_BASE64:
        {
            // In base64 encoding, 6-bit words are packed into bytes using a
            // 4-in-3 byte arrangement as shown here:
            //
            //         word index=1
            //               |
            //            -------
            //      00000011 11112222 22333333  
            //       AByte    BByte    CByte
            //
            // where: 
            //
            //      000000 is the first 6-bit word, 111111 is the second, and 
            //             so on.
            
            // Compute which of the four positions in a 24-bit group will be
            // filled in next based on how many 6-bit words have been written 
            // to the file so far.
            // 
            // FilePositionIn6BitWords is the current offset from the beginning 
            // of the file in terms of 6-bit words, ignoring whitespace and 
            // padding.
            //
            // The least significant two bits of the 6-bit-word file position 
            // is a word index that refers to a 6-bit word in a 24-bit field.
            WordIndex = F->FilePositionIn6BitWords & 3;
            
            // Handle each of the four positions separately.
            switch( WordIndex )
            {
                case 0:
                {
                    //      ======
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                    //
                    // Store the input byte in AByte.
                    F->AByte = ByteToWrite;
                    
                    // Look up the ASCII base64 equivalent of 6-bit word 0.
                    Letter = base64Alphabet[ F->AByte >> 2 ];
                    
                    // Write the letter to the file at the current file 
                    // position, returning the number of bytes written.
                    NumberWritten = WriteByte( F->FileHandle, Letter );
                    
                    // If the letter was written to the file, advance the
                    // 6-bit word file position by one.
                    if( NumberWritten == 1 )
                    {
                        F->FilePositionIn6BitWords++;
                    }
                    
                    // All done with this case, skip over the other cases.
                    break;
                }
                
                //--------------------------------------------------------------
                 
                case 1:
                {
                    //            =======
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                    //
                    // Store the input byte in BByte.
                    F->BByte = ByteToWrite;
                    
                    // Combine parts of AByte and BByte into 6-bit word 1.
                    i = ( (F->AByte & 3) << 4 ) | (F->BByte >> 4);
                    
                    // Look up the ASCII base64 equivalent of 6-bit word 1.
                    Letter = base64Alphabet[i];
                    
                    // Write the letter to the file at the current file 
                    // position, returning the number of bytes written.
                    NumberWritten = WriteByte( F->FileHandle, Letter );
                    
                    // If the letter was written to the file, advance the
                    // 6-bit word file position by one.
                    if( NumberWritten == 1 )
                    {
                        F->FilePositionIn6BitWords++;
                    }
                    
                    // All done with this case, skip over the other cases.
                    break;
                }
                
                //--------------------------------------------------------------
                 
                case 2: // and 3.
                {
                    //                   =============
                    //      00000011 11112222 22333333  
                    //       AByte    BByte    CByte
                    //
                    // Store the input byte in CByte.
                    F->CByte = ByteToWrite;
                    
                    // Combine parts of BByte and CByte into 6-bit word 2.
                    i = ( (F->BByte & 0xF) << 2 ) | (F->CByte >> 6);
                    
                    // Look up the ASCII base64 equivalent of 6-bit word 2.
                    Letter = base64Alphabet[i];
                    
                    // Write the letter to the file at the current file 
                    // position, returning the number of bytes written.
                    NumberWritten = WriteByte( F->FileHandle, Letter );
                    
                    // If the letter was written to the file, advance the
                    // 6-bit word file position by one.
                    if( NumberWritten == 1 )
                    {
                        F->FilePositionIn6BitWords++;
                    } 
                    else // Unable to write the byte.
                    {
                        // Skip the attempt to write 6-bit word 3.
                        break;
                    } 
                    
                    // 6-bit word 3 is also in CByte,
                    
                    // Look up the ASCII base64 equivalent of 6-bit word 3.
                    Letter = base64Alphabet[F->CByte & 0x3F];
                    
                    // Write the letter to the file at the current file 
                    // position, returning the number of bytes written.
                    NumberWritten = WriteByte( F->FileHandle, Letter );
                    
                    // If the letter was written to the file, advance the
                    // 6-bit word file position by one.
                    if( NumberWritten == 1 )
                    {
                        F->FilePositionIn6BitWords++;
                    } 
                    
                    // All done with this case.
                    break;
                }
                
            } // switch( WordIndex )
          
            // If data has been written to the file, then check to see if 
            // end-of-line characters need to be inserted.
            if( NumberWritten )
            {
                // If 76 letters have been written on the current line, then
                // insert a CR+LF. 76 is the RFC 2045 line length limit.
                if( (F->FilePositionIn6BitWords % BASE64_LINE_LENGTH ) == 0 )
                {
                    // Write a CR byte to the file returning the number of 
                    // bytes written.
                    NumberWritten = WriteByte( F->FileHandle, CarriageReturn );

                    // If able to write the CR, then write the LF.
                    if( NumberWritten == 1 )
                    {
                        // Write LF byte to the file returning the number of 
                        // bytes written.
                        NumberWritten = WriteByte( F->FileHandle, LineFeed );
                    }
                }
            }
        }
            
    } // switch( X->FileFormat )
 
    // Return the number of bytes written: either 1 or 0 if there was an error.
    return( NumberWritten );
}

/*------------------------------------------------------------------------------
| WriteListOfTextLines
|-------------------------------------------------------------------------------
|
| PURPOSE: To write a list of strings to a text file.
|
| DESCRIPTION: Strings are written line-by-line with end-of-line characters
| added by this routine. 
|
| In other words, it's assumed that the strings don't already include 
| end-of-line characters.
|
| Returns a result code: 0 if OK, otherwise an error code.
|
| EXAMPLE:  
|             Result = WriteListOfTextLines( "MyData.txt", StringList );
| HISTORY: 
|    25Jan14 From ReadListOfTextLines(). 
------------------------------------------------------------------------------*/
      // OUT: RESULT_OK if OK, otherwise an error code.
u32   //
WriteListOfTextLines( 
    s8* AFileName,
            // File name, a zero-terminated ASCII string.
            //
    List* L )
            // A list of strings to be written.
{
    FILE* AFile;
    s16 ByteCount;
    u32 BytesWritten;
    ThatItem C;
    s32 Status;
            
    // Just return if there is nothing to write to the file.
    if( (L == 0) || (L->ItemCount == 0) )
    {
        return( RESULT_OK );
    }
    
    // Open the output file to write binary data.
    AFile = fopen64( AFileName, "wb" );

    // If unable to open the file, return RESULT_CANT_OPEN_FILE_FOR_WRITING.
    if( AFile == 0 )
    {
        return( RESULT_CANT_OPEN_FILE_FOR_WRITING );
    }
    
    // Refer to the first string in the list using cursor C.
    ToFirstItem( L, &C ); 

    // Continue writing lines until the end of the list is reached or an
    // error occurs.
    while( C.TheItem )
    {
        // Measure the size of the string to be written.
        ByteCount = strlen( (s8*) C.TheItem->DataAddress );
        
        // If the string with end-of-line bytes can't fit in the text line 
        // buffer, then return with an error code.
        if( (ByteCount + 2) > TEXT_LINE_BUFFER_SIZE )
        {
              // Close the file.
            fclose( AFile );
            
               // Return the error code for put a strint into the line buffer.
            return( RESULT_TEXT_LINE_TOO_LONG_FOR_BUFFER );
        }
        
        // Format the output string to append an end-of-line sequence.
        sprintf( &TextLineBuffer[0], 
                 "%s\n", 
                 C.TheItem->DataAddress );
 
        // Count the number of bytes in the string, not including the zero
        // terminator.
        ByteCount = strlen( &TextLineBuffer[0] );
         
        // Write the line to the output file.
        BytesWritten = 
            WriteBytes( AFile,
                        (u8*) &TextLineBuffer[0],
                        ByteCount );
           
        // If the wrong number of bytes were written, then fail with an
        // error code.
        if( BytesWritten != ByteCount ) 
        {
              // Close the file.
            fclose( AFile );
            
               // Return the error code for not being able to write to a
               // file.
            return( RESULT_CANT_WRITE_FILE );
        }
            
        // Advance the item cursor to the next string in the list.           
        ToNextItem(&C);
    }
 
     // Close the output file.
    Status = fclose( AFile );
         
    // If unable to close the file properly, then return an error code.
    if( Status )
    {
        // Return the error code.
        return( RESULT_CANT_CLOSE_FILE );
    }
     
    // Successful, return the OK result code.
    return( RESULT_OK );
}
 
/*------------------------------------------------------------------------------
| XorBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To XOR one block of bytes with another.
|
| DESCRIPTION: Correctly handles an overlapping series of bytes. 
|
| EXAMPLE:                   XorBytes( From, To, 5 );
|
| HISTORY: 
|    18Feb14 From CopyBytes().
------------------------------------------------------------------------------*/
void
XorBytes( u8* From, u8* To, u32 Count )
{
    if( From >= To )
    {
        while( Count-- )
        {
            *To++ ^= *From++;
        }
    }
    else
    {
        To   += Count;
        From += Count;
        
        while( Count-- )
        {
            *--To ^= *--From;
        }
    }
}
 
/*------------------------------------------------------------------------------
| ZeroBytes
|-------------------------------------------------------------------------------
|
| PURPOSE: To fill a buffer with zeros.
|
| DESCRIPTION: This is a convenience routine that is probably slower than 
| memset() for large buffers.
|
| HISTORY: 
|    29May01 
-----------------------------------------------------------------------------*/
void
ZeroBytes( u8* Destination, u32 AByteCount )
{
    while( AByteCount-- )
    {
        *Destination++ = 0;
    }
}

/*------------------------------------------------------------------------------
| ZeroAllNumericParameters
|-------------------------------------------------------------------------------
|
| PURPOSE: To zero all numeric parameters, marking them as unspecified.
|
| DESCRIPTION:  
|           
| HISTORY: 
|    21Feb14 Factored out of ZeroAndFreeAllBuffers() and InitializeParameters().
------------------------------------------------------------------------------*/
void
ZeroAllNumericParameters()
{
    u32 i;
    
    // Start with the first item in the list of all numeric parameters.
    i = 0;
    
    // Process each item in the table of all numeric parameters. The list is
    // terminated with a zero.
    while( NumericParameters[i] )
    {
        // Mark the numeric parameter as not having been specified.
        NumericParameters[i]->IsSpecified = 0;
        
        // Set the parameter to 0 as a generic default value.
        NumericParameters[i]->Value = 0;
    
        // Advance to the next item in the table.
        i++;
    }
}

/*------------------------------------------------------------------------------
| ZeroAllStringListParameters
|-------------------------------------------------------------------------------
|
| PURPOSE: To zero all string list parameters, marking them as unspecified.
|
| DESCRIPTION:  
|           
| HISTORY: 
|    21Feb14 Factored out of InitializeParameters().
------------------------------------------------------------------------------*/
void
ZeroAllStringListParameters()
{
    u32 i;
     
    // Start with the first item in the list of all string list parameters.
    i = 0;
    
    // Process each item in the table of all string list parameters. The table
    // is terminated with a zero.
    while( StringListParameters[i] )
    {
        // Mark the string parameter as not having been specified.
        StringListParameters[i]->IsSpecified = 0;
        
        // Initialize the parameter to be zero.
        StringListParameters[i]->Value = 0;
    
        // Advance to the next item in the table.
        i++;
    }
}

/*------------------------------------------------------------------------------
| ZeroAllStringParameters
|-------------------------------------------------------------------------------
|
| PURPOSE: To zero all string parameters, marking them as unspecified.
|
| DESCRIPTION:  
|           
| HISTORY: 
|    21Feb14 Factored out of InitializeParameters().
------------------------------------------------------------------------------*/
void
ZeroAllStringParameters()
{
    u32 i;
    
    // Start with the first item in the list of all string parameters.
    i = 0;
    
    // Process each item in the table of all string parameters. The list is
    // terminated with a zero.
    while( StringParameters[i] )
    {
        // Mark the string parameter as not having been specified.
        StringParameters[i]->IsSpecified = 0;
        
        // Set the parameter to a generic default value of 0.
        StringParameters[i]->Value = 0;
    
        // Advance to the next item in the table.
        i++;
    }
}
/*------------------------------------------------------------------------------
| ZeroAndFreeAllBuffers
|-------------------------------------------------------------------------------
|
| PURPOSE: To fill all working buffers in the OT7 application with zeros.
|
| DESCRIPTION: Use this routine before parsing the command line, and then later
| to wipe any data that might be left in memory buffers following an 
| encryption/decryption process. 
|
| Dynamically allocated buffers are deallocated after being filled with zeros.
|
| It is assumed that the parameters have been initialized by 
| InitializeParameters() at some point prior to calling this routine.
|
| This routine doesn't zero the variable Result because it is needed to pass 
| back completion status when the application exits.
|
| HISTORY: 
|    03Nov13 
|    19Jan14 Added clean up of numeric parameters, strings, and lists.
|    10Feb14 Added KeyHashBuffer.
|    15Feb14 Added PasswordContext and SumZContext.
|    16Feb14 Added PseudoRandomKeyBuffer.
|    17Feb14 Added FillBuffer.
|    21Feb14 Revised to use ZeroAllNumbericParameters().
|    04Mar14 Added HexStringBuffer.
|    17Mar14 Moved many buffers to OT7Context records.
------------------------------------------------------------------------------*/
void
ZeroAndFreeAllBuffers()
{
    u16 i;
     
    // Zero the HexStringBuffer.
    ZeroBytes( (u8*) HexStringBuffer, HEX_STRING_BUFFER_SIZE );
      
    // Zero the TextLineBuffer.
    ZeroBytes( (u8*) TextLineBuffer, TEXT_LINE_BUFFER_SIZE );
     
    //--------------------------------------------------------------------------

    // Zero all numeric parameters, marking them as unspecified.
    ZeroAllNumericParameters();
     
    //--------------------------------------------------------------------------
    // Deallocate all string parameters.
    
    // Start with the first item in the list of all string parameters.
    i = 0;
    
    // Process each item in the table of all string parameters. The list is
    // terminated with a zero.
    while( StringParameters[i] )
    {
        // If the string buffer exists, then zero it and free it.
        if( StringParameters[i]->Value )
        {
            // Zero fill the string and deallocate it.
            DeleteString( StringParameters[i]->Value );
        }
     
        // Advance to the next item in the table.
        i++;
    }
    
    // Zero all string parameters, marking them as unspecified.
    ZeroAllStringParameters();
    
    //--------------------------------------------------------------------------
    // Deallocate all string list parameters.
    
    // Start with the first item in the list of all string list parameters.
    i = 0;
    
    // Process each item in the table of all string list parameters. The table
    // is terminated with a zero.
    while( StringListParameters[i] )
    {
        // If the string list exists, then zero it and free it.
        if( StringListParameters[i]->Value )
        {
            // Zero fill the string list.
            ZeroFillStringList( StringListParameters[i]->Value );
            
            // Deallocate the string list.
            DeleteListOfDynamicData( StringListParameters[i]->Value );
        }
     
        // Advance to the next item in the table.
        i++;
    }
    
    // Zero all string list parameters, marking them as unspecified.
    ZeroAllStringListParameters();
}

/*------------------------------------------------------------------------------
| ZeroFillString
|-------------------------------------------------------------------------------
|
| PURPOSE: To fill a string buffer with zero bytes.
|
| DESCRIPTION: Fills all of the bytes prior to the first zero byte with zero
| bytes.
|           
| HISTORY: 
|    26Jan14  
------------------------------------------------------------------------------*/
void
ZeroFillString( s8* S )
{
    // If a valid string address has been given, then zero the string.
    if( S )
    {
        // If the current byte of the string is non-zero, then fill it with
        // zero and advance to the next byte.
        while( *S )
        {
            *S++ = 0;
        }
    }
}

/*------------------------------------------------------------------------------
| ZeroFillStringList
|-------------------------------------------------------------------------------
|
| PURPOSE: To fill all strings in a list with zero bytes.
|
| DESCRIPTION: The input list refers to string buffers. Each string buffer is
| filled with zero bytes by this routine.
|           
| HISTORY: 
|    19Jan14 From DeleteEmptyStringsInStringList().
|    26Jan14 Revised to call ZeroFillString().
|    28Feb14 Now addresses string through DataAddress field instead of 
|            BufferAddress.
------------------------------------------------------------------------------*/
void
ZeroFillStringList( List* L ) // A list of strings.
{
    ThatItem C;
     
    // If a valid list address has been given, the zero the string list.
    if( L )
    {
        // Refer to the first item in the list.
        ToFirstItem( L, &C );
        
        // For each string in the list.
        while( C.TheItem )
        {
            // Zero fill the string buffer.
            ZeroFillString( (s8*) C.TheItem->DataAddress );
              
            // Advance to the next string in the list.
            ToNextItem(&C);
        }
    }
}

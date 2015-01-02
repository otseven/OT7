/* https://github.com/otseven/OT7            
    
--------------------------------------------------------------------------------
ot7test.c - TEST PROGRAM FOR OT7 ENCRYPTION TOOL                 January 2, 2015
--------------------------------------------------------------------------------

PURPOSE: To test the OT7 encryption tool.

DESCRIPTION: This is a separate program that calls the OT7 application to make
sure it's working properly.

Test encryption keys and plaintext files are pseudo-randomly generated during 
this test. Many different ways of using OT7 are tested with this generated data.

21MB of disk space is required for this test. 

This test can take an hour or more to run depending on the speed of the 
computer.
 
The test ends early with an error message if any error is detected.
 
------------------------------------------------------------------------------*/

#define APPLICATION_NAME_STRING "ot7test"
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
    #define fseeko64    fseeko
    #define ftello64    ftello
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

//------------------------------------------------------------------------------
// PSEUDO-RANDOM NUMBER GENERATOR
//------------------------------------------------------------------------------

#define PSEUDO_RANDOM_DATA_BUFFER_SIZE  1024
    // Size in bytes of the pseudo-random number data buffer.

#define PSEUDO_RANDOM_BUFFER_BIT_COUNT (PSEUDO_RANDOM_DATA_BUFFER_SIZE << 3)
    // Size in bits of the pseudo-random number data buffer.

u8 PseudoRandomDataBuffer[PSEUDO_RANDOM_DATA_BUFFER_SIZE]; // 1024 bytes
    // Buffer for bytes produced by the pseudo-random number generator. Data
    // is generated in blocks of 1024 bytes and then used one at a time.
 
u32 PseudoRandomDataBufferByteCount;
    // Number of data bytes in the PseudoRandomDataBuffer. Bytes are removed in
    // order from the start of the buffer to the end.
 
Skein1024Context PseudoRandomHashContext;
    // Hash context for generating pseudo-random test data such as plaintext
    // files and encryption key files.
  
//------------------------------------------------------------------------------
// RESULT CODES
//------------------------------------------------------------------------------
 
int Result;
    // Result code returned when the application exits, one of the following
    // values. Applications calling the ot7 command line tool can use these
    // result codes in error handling routines.
    //
    // Zero is reserved to mean successful completion. Error numbers start at 
    // 1 to fit into a byte and avoid collision with the range used by
    // sysexits.h which starts at 64.
 
#define RESULT_OK 0 
            // Use 0 for no error result for compatibility with other
            // applications.
                 
#define RESULT_CANT_CLOSE_ENCRYPTED_FILE               1
#define RESULT_CANT_CLOSE_FILE                         2
#define RESULT_CANT_CLOSE_KEY_FILE                     3
#define RESULT_CANT_CLOSE_PLAINTEXT_FILE               4
#define RESULT_CANT_IDENTIFY_KEYADDRESS_FOR_DECRYPTION 5
#define RESULT_CANT_IDENTIFY_KEYID_FOR_DECRYPTION      6
#define RESULT_CANT_IDENTIFY_KEYID_FOR_ENCRYPTION      7
#define RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING    8
#define RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_WRITING    9
#define RESULT_CANT_OPEN_FILE_FOR_WRITING              10
#define RESULT_CANT_OPEN_KEY_FILE_FOR_READING          11
#define RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING          12
#define RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_READING    13
#define RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_WRITING    14
#define RESULT_CANT_READ_ENCRYPTED_FILE                15
#define RESULT_CANT_READ_KEY_FILE                      16
#define RESULT_CANT_READ_KEY_MAP_FILE                  17
#define RESULT_CANT_READ_PLAINTEXT_FILE                18
#define RESULT_CANT_SEEK_IN_ENCRYPTED_FILE             19
#define RESULT_CANT_SEEK_IN_KEY_FILE                   20
#define RESULT_CANT_SEEK_IN_PLAINTEXT_FILE             21
#define RESULT_CANT_WRITE_ENCRYPTED_FILE               22
#define RESULT_CANT_WRITE_FILE                         23
#define RESULT_CANT_WRITE_KEY_FILE                     24
#define RESULT_CANT_WRITE_PLAINTEXT_FILE               25
#define RESULT_CANT_ERASE_USED_KEY_BYTES               26
#define RESULT_INVALID_CHECKSUM_DECRYPTED              27
#define RESULT_INVALID_COMMAND_LINE_PARAMETER          28
#define RESULT_INVALID_COMPUTED_HEADER_KEY             29
#define RESULT_INVALID_DECRYPTION_OUTPUT               30
#define RESULT_INVALID_ENCRYPTED_FILE_FORMAT           31
#define RESULT_INVALID_KEY_FILE_NAME                   32
#define RESULT_INVALID_KEY_FILE_POINTER                33
#define RESULT_INVALID_KEY_MAP_FILE_NAME               34
#define RESULT_INVALID_LOG_FILE_NAME                   35
#define RESULT_INVALID_NAME_OF_FILE_TO_DECRYPT         36
#define RESULT_INVALID_NAME_OF_PLAINTEXT_FILE          37
#define RESULT_INVALID_OUTPUT_FILE_NAME                38
#define RESULT_KEY_FILE_IS_TOO_SMALL                   39
#define RESULT_MISSING_COMMAND_LINE_PARAMETER          40
#define RESULT_MISSING_KEYID_IN_KEYDEF_STRING          41
#define RESULT_NO_COMMAND_LINE_PARAMETERS_GIVEN        42
#define RESULT_OUT_OF_MEMORY                           43
#define RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD          44
#define RESULT_SKEIN_TEST_FINAL_RESULT_IS_INVALID      45
#define RESULT_SKEIN_TEST_INITIALIZATION_FAILED        46
#define RESULT_TEXT_LINE_TOO_LONG_FOR_BUFFER           47
 
/*------------------------------------------------------------------------------
| ResultCodeAndString
|-------------------------------------------------------------------------------
|
| PURPOSE: To associate a result code with a name string.
|
| DESCRIPTION: 
|
| HISTORY: 
|    25Dec14
------------------------------------------------------------------------------*/
typedef struct
{
    u32 ResultCode;   
            // A 32-bit result code.
 
    s8* ResultCodeString;    
            // The name of the result code an ASCIIZ string.
            
} ResultCodeAndString;
  
/*------------------------------------------------------------------------------
| ResultCodesOT7
|-------------------------------------------------------------------------------
|
| PURPOSE: To associate OT7 result codes with name strings.
|
| DESCRIPTION: OT7 passes a result code to the calling application or shell 
| when it exits. This table is used to convert that number to a human readable
| string.
|
| HISTORY: 
|    25Dec14
------------------------------------------------------------------------------*/
ResultCodeAndString
ResultCodesOT7[] =
{
    { RESULT_OK, 
     "RESULT_OK" },
     
    { RESULT_CANT_CLOSE_ENCRYPTED_FILE, 
     "RESULT_CANT_CLOSE_ENCRYPTED_FILE" },
     
    { RESULT_CANT_CLOSE_FILE, 
     "RESULT_CANT_CLOSE_FILE" }, 
                             
    { RESULT_CANT_CLOSE_KEY_FILE, 
     "RESULT_CANT_CLOSE_KEY_FILE" },
     
    { RESULT_CANT_CLOSE_PLAINTEXT_FILE, 
     "RESULT_CANT_CLOSE_PLAINTEXT_FILE" }, 
       
    { RESULT_CANT_IDENTIFY_KEYADDRESS_FOR_DECRYPTION, 
     "RESULT_CANT_IDENTIFY_KEYADDRESS_FOR_DECRYPTION" },
     
    { RESULT_CANT_IDENTIFY_KEYID_FOR_DECRYPTION, 
     "RESULT_CANT_IDENTIFY_KEYID_FOR_DECRYPTION" }, 
     
    { RESULT_CANT_IDENTIFY_KEYID_FOR_ENCRYPTION, 
     "RESULT_CANT_IDENTIFY_KEYID_FOR_ENCRYPTION" },  
         
    { RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING, 
     "RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_READING" },  
       
    { RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_WRITING, 
     "RESULT_CANT_OPEN_ENCRYPTED_FILE_FOR_WRITING" },  
       
    { RESULT_CANT_OPEN_FILE_FOR_WRITING, 
     "RESULT_CANT_OPEN_FILE_FOR_WRITING" },
      
    { RESULT_CANT_OPEN_KEY_FILE_FOR_READING, 
     "RESULT_CANT_OPEN_KEY_FILE_FOR_READING" },
      
    { RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING, 
     "RESULT_CANT_OPEN_KEY_FILE_FOR_WRITING" },
              
    { RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_READING, 
     "RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_READING" },
     
    { RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_WRITING, 
     "RESULT_CANT_OPEN_PLAINTEXT_FILE_FOR_WRITING" },
     
    { RESULT_CANT_READ_ENCRYPTED_FILE, 
     "RESULT_CANT_READ_ENCRYPTED_FILE" },   
     
    { RESULT_CANT_READ_KEY_FILE, 
     "RESULT_CANT_READ_KEY_FILE" },
                           
    { RESULT_CANT_READ_KEY_MAP_FILE, 
     "RESULT_CANT_READ_KEY_MAP_FILE" },
       
    { RESULT_CANT_READ_PLAINTEXT_FILE, 
     "RESULT_CANT_READ_PLAINTEXT_FILE" }, 
     
    { RESULT_CANT_SEEK_IN_ENCRYPTED_FILE, 
     "RESULT_CANT_SEEK_IN_ENCRYPTED_FILE" }, 
      
    { RESULT_CANT_SEEK_IN_KEY_FILE, 
     "RESULT_CANT_SEEK_IN_KEY_FILE" },
          
    { RESULT_CANT_SEEK_IN_PLAINTEXT_FILE,
     "RESULT_CANT_SEEK_IN_PLAINTEXT_FILE" },  
     
    { RESULT_CANT_WRITE_ENCRYPTED_FILE,
     "RESULT_CANT_WRITE_ENCRYPTED_FILE" },   
     
    { RESULT_CANT_WRITE_FILE,
     "RESULT_CANT_WRITE_FILE" },  
     
    { RESULT_CANT_WRITE_KEY_FILE,
     "RESULT_CANT_WRITE_KEY_FILE" },    
     
    { RESULT_CANT_WRITE_PLAINTEXT_FILE,
     "RESULT_CANT_WRITE_PLAINTEXT_FILE" },     
     
    { RESULT_CANT_ERASE_USED_KEY_BYTES,
     "RESULT_CANT_ERASE_USED_KEY_BYTES" }, 
     
    { RESULT_INVALID_CHECKSUM_DECRYPTED,
     "RESULT_INVALID_CHECKSUM_DECRYPTED" }, 
     
    { RESULT_INVALID_COMMAND_LINE_PARAMETER,
     "RESULT_INVALID_COMMAND_LINE_PARAMETER" }, 
     
    { RESULT_INVALID_COMPUTED_HEADER_KEY,
     "RESULT_INVALID_COMPUTED_HEADER_KEY" },   
     
    { RESULT_INVALID_DECRYPTION_OUTPUT,
     "RESULT_INVALID_DECRYPTION_OUTPUT" },   
     
    { RESULT_INVALID_ENCRYPTED_FILE_FORMAT,
     "RESULT_INVALID_ENCRYPTED_FILE_FORMAT" },      
     
    { RESULT_INVALID_KEY_FILE_NAME,
     "RESULT_INVALID_KEY_FILE_NAME" },  
     
    { RESULT_INVALID_KEY_FILE_POINTER,
     "RESULT_INVALID_KEY_FILE_POINTER" }, 
     
    { RESULT_INVALID_KEY_MAP_FILE_NAME,
     "RESULT_INVALID_KEY_MAP_FILE_NAME" }, 
     
    { RESULT_INVALID_LOG_FILE_NAME,
     "RESULT_INVALID_LOG_FILE_NAME" },  
     
    { RESULT_INVALID_NAME_OF_FILE_TO_DECRYPT,
     "RESULT_INVALID_NAME_OF_FILE_TO_DECRYPT" }, 
     
    { RESULT_INVALID_NAME_OF_PLAINTEXT_FILE,
     "RESULT_INVALID_NAME_OF_PLAINTEXT_FILE" }, 
     
    { RESULT_INVALID_OUTPUT_FILE_NAME,
     "RESULT_INVALID_OUTPUT_FILE_NAME" }, 
     
    { RESULT_KEY_FILE_IS_TOO_SMALL,
     "RESULT_KEY_FILE_IS_TOO_SMALL" }, 
     
    { RESULT_MISSING_COMMAND_LINE_PARAMETER,
     "RESULT_MISSING_COMMAND_LINE_PARAMETER" }, 
     
    { RESULT_MISSING_KEYID_IN_KEYDEF_STRING,
     "RESULT_MISSING_KEYID_IN_KEYDEF_STRING" }, 
     
    { RESULT_NO_COMMAND_LINE_PARAMETERS_GIVEN,
     "RESULT_NO_COMMAND_LINE_PARAMETERS_GIVEN" },  
     
    { RESULT_OUT_OF_MEMORY,
     "RESULT_OUT_OF_MEMORY" },  
     
    { RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD,
     "RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD" }, 
     
    { RESULT_SKEIN_TEST_FINAL_RESULT_IS_INVALID,
     "RESULT_SKEIN_TEST_FINAL_RESULT_IS_INVALID" }, 
     
    { RESULT_SKEIN_TEST_INITIALIZATION_FAILED,
     "RESULT_SKEIN_TEST_INITIALIZATION_FAILED" }, 
     
    { RESULT_TEXT_LINE_TOO_LONG_FOR_BUFFER,
     "RESULT_TEXT_LINE_TOO_LONG_FOR_BUFFER" }, 
     
    { 0, 0 } // This record marks the end of the list.
};

s8*   ConvertIntegerToString64( u64 n );
u8    GeneratePseudoRandomByte();
u32   GenerateRandomFile( s8* FileName, u64 FileSize );
u64   Get_u64_LSB_to_MSB( u8* Buffer );
u64   GetFileSize64( FILE* F );
void  InitPseudoRandomGenerator( u8* Seed, u32 ByteCount );
u32   IsFilesIdentical( s8* AFileName, s8* BFileName );
s8*   LookUpResultCodeString( int ResultCode );
int   main( int argc, char* argv[] );
void  Put_u64_LSB_to_MSB( u64 n, u8* Buffer );
u32   ReadByte( FILE* FileHandle, u8* BufferAddress );
u32   ReadBytes( FILE* FileHandle, u8* BufferAddress, u32 NumberOfBytes );
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
int   Test( s8* CommandLineString, int ExpectedResultCode );

int   TestEncryptDecryptFile( 
            u64 FileSize, 
            s8* EncryptionCommandString,
            s8* DecryptionCommandString );

void TestEncryptDecryptFiles_DefaultOptions( 
            u64 StartFileSize, 
            u64 EndFileSize, 
            u64 SizeIncrement );
            
void TestEncryptDecryptFiles_EncryptedFileFormatBinary( 
            u64 StartFileSize, 
            u64 EndFileSize, 
            u64 SizeIncrement );
            
void TestEncryptDecryptFiles_EncryptedFileFormatBase64( 
            u64 StartFileSize, 
            u64 EndFileSize, 
            u64 SizeIncrement );
            
void TestEncryptDecryptFiles_NoFileName( 
            u64 StartFileSize, 
            u64 EndFileSize, 
            u64 SizeIncrement );
             
u32   WriteByte( FILE* FileHandle, u8 AByte );
u32   WriteBytes( FILE* FileHandle, u8* BufferAddress, u32 AByteCount );
void  ZeroBytes( u8* Destination, u32 AByteCount );
 
/*------------------------------------------------------------------------------
| main
|-------------------------------------------------------------------------------
|
| PURPOSE: Main routine for OT7 test program.
|
| DESCRIPTION: This is a separate program that calls the OT7 application to 
| make sure it's working properly.
|
| Test encryption keys and plaintext files are pseudo-randomly generated during 
| this test.
|  
| Many different ways of using OT7 are tested with this generated data and test
| results are printed to standard output.
|
| 21MB of disk space are required for this test. 
|
| This test can take an hour or more to run depending on the speed of the 
| computer.
|
| The test ends early if any error is detected.
|
| HISTORY: 
|    26Dec14
------------------------------------------------------------------------------*/
    // OUT: Result code from interpreting the command line function.
int //
main( int argc, char* argv[] )
{
    (void) argc;
    (void) argv;
    
    // Run OT7 with no command line parameters, expecting an error as a result.
    Test( "./ot7", RESULT_NO_COMMAND_LINE_PARAMETERS_GIVEN );
            
    // Test the option that suppresses all output.
    Test( "./ot7 -silent", RESULT_OK );
      
    // Test the hash function used by the crypto routines. 
    Test( "./ot7 -testhash", RESULT_OK );
      
    // Test help request option, expecting no error as a result.
    Test( "./ot7 -h", RESULT_OK );
       
    // Initialize the pseudo-random number generator using "Seed" as the 
    // initialization vector.
    InitPseudoRandomGenerator( (u8*) "Seed", 4 );

    printf( "Generating a 30,000 byte encryption key file named '123.key'.\n" );
     
    // Generate a 30,000,000 byte key file named '123.key' for use by 
    // TestEncryptDecryptFile_BinaryFormat() below.
    GenerateRandomFile( "123.key", 30000LL );

    printf( "Range across OT7 crypto options using a series of small \n" );
    printf( "plaintext files.\n" );
    
    TestEncryptDecryptFiles_DefaultOptions( 1LL, 10LL, 1LL );
    TestEncryptDecryptFiles_NoFileName( 1LL, 10LL, 1LL );
    TestEncryptDecryptFiles_EncryptedFileFormatBinary( 1LL, 10LL, 1LL );
    TestEncryptDecryptFiles_EncryptedFileFormatBase64( 1LL, 10LL, 1LL );
    
    printf( "Generating a 20,000,000 byte encryption key file named '123.key'.\n" );
     
    // Generate a 20,000,000 key file named '123.key' for use by 
    // TestEncryptDecryptFile_BinaryFormat() below.
    GenerateRandomFile( "123.key", 20000000LL );

    printf( "Test encryption of every plaintext file size from 11 to 2100.\n" );
    printf( "This test is looking for any special case failures associated\n" );
    printf( "with sizes of the working buffers used in OT7.\n" );
    
    TestEncryptDecryptFiles_DefaultOptions( 11LL, 2100LL, 1LL );
    TestEncryptDecryptFiles_NoFileName( 11LL, 2100LL, 1LL );
    TestEncryptDecryptFiles_EncryptedFileFormatBinary( 11LL, 2100LL, 1LL );
    TestEncryptDecryptFiles_EncryptedFileFormatBase64( 11LL, 2100LL, 1LL );
    
    printf( "Generating a 10,000,000 byte encryption key file named '123.key'.\n" );
     
    // Generate a 10,000,000 key file named '123.key' for use by 
    // TestEncryptDecryptFile_BinaryFormat() below.
    GenerateRandomFile( "123.key", 10000000LL );

    printf( "Test encryption of plaintext file sizes spanning the 64K boundary.\n" );
     
    TestEncryptDecryptFiles_DefaultOptions( 0xFFF0LL, 0x10005LL, 1LL );
    TestEncryptDecryptFiles_NoFileName( 0xFFF0LL, 0x10005LL, 1LL );
    TestEncryptDecryptFiles_EncryptedFileFormatBinary( 0xFFF0LL, 0x10005LL, 1LL );
    TestEncryptDecryptFiles_EncryptedFileFormatBase64( 0xFFF0LL, 0x10005LL, 1LL );
     
    // Getting to this point implies success with Result = RESULT_OK (0).

    printf( "All tests passed OK.\n" );
         
    printf( "Exiting OT7 test program with result code %d = %s.\n", 
            Result,
            LookUpResultCodeString( Result ) );
   
    // Return result code to the calling application.
    return( Result );
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
| GeneratePseudoRandomByte
|-------------------------------------------------------------------------------
|
| PURPOSE: To generate a pseudo-random byte from the range 0 to 255 inclusive.
|
| DESCRIPTION: This implementation uses a Skein1024 hash function as a pseudo-
| random number generator. Any other method could be used here to produce test
| data, but the Skein routines are handy since they have already been tested 
| using the test in OT7.c.
| 
| Before using this routine, call InitPseudoRandomGenerator() to initialize
| the hash context and buffer pointer.
|
| HISTORY: 
|    27Dec14 From GetNextByteFromPasswordHashStream() in OT7.c.
------------------------------------------------------------------------------*/
    // OUT: The next pseudo-random byte.
u8  // 
GeneratePseudoRandomByte()
{
    u8 AByte;
    
    // If there are no bytes in the pseudo-random data buffer, then generate a  
    // block from the pseudo-random hash context.
    if( PseudoRandomDataBufferByteCount == 0 )
    {
        // Generate pseudo-random bytes to the PseudoRandomDataBuffer.
        Skein1024_Final( &PseudoRandomHashContext, 
                         (u8*) &PseudoRandomDataBuffer );

        // Reset the content counter for the PseudoRandomDataBuffer to indicate
        // that the buffer is full of data.
        PseudoRandomDataBufferByteCount = PSEUDO_RANDOM_DATA_BUFFER_SIZE;
    }
    
    // Fetch the next byte from the pseudo-random data buffer.
    AByte = PseudoRandomDataBuffer[PSEUDO_RANDOM_DATA_BUFFER_SIZE - 
                                   PseudoRandomDataBufferByteCount]; 
                                
    // Account for using one of the pseudo-random data bytes.
    PseudoRandomDataBufferByteCount--;
    
    // Return the byte.
    return( AByte );
}

/*------------------------------------------------------------------------------
| GenerateRandomFile
|-------------------------------------------------------------------------------
|
| PURPOSE: To generate a file filled with pseudo-random bytes.
|
| DESCRIPTION: The data written to the file is unformatted binary values in the
| full range from 0 to 255 inclusive.
|
| This generator is intended for testing purposes only. It is not safe for 
| making actual OT7 encryption keys, so use a true random number generator for 
| that. 
|
| HISTORY: 
|    28Dec14 
------------------------------------------------------------------------------*/
    // OUT: Result code RESULT_OK if successful, or an error code if not.
u32 // 
GenerateRandomFile( s8* FileName, u64 FileSize )
{
    FILE* F;
    u64   i;
    u32   BytesWritten;

    // Open an output file to write binary data.
    F = fopen64( FileName, "wb" );

    // If file was opened OK, write pseudo-random data to the file.
    if( F )
    {
        // Write enough bytes to make a file of the given size.
        for( i = 0; i < FileSize; i++ )
        {
            // Write one byte to the file.
            BytesWritten = WriteByte( F, GeneratePseudoRandomByte() );
            
            // If the byte was not written, then close the file and return
            // an error result code.
            if( BytesWritten != 1 )
            {
                // Close the file, leaving any partially written file on disk.
                fclose( F );
                
                // Return an error code that means the file could not be 
                // written.
                return( RESULT_CANT_WRITE_FILE );
            }
        }
        
        // Close the file after having written the whole file to disk.
        fclose( F );
        
        // Return a result code meaning successful completion.
        return( RESULT_OK );
    }
    else // Unable to open the file for writing, so return an error code.
    {
        // Return an error code that means the file could not be opened
        // for writing.
        return( RESULT_CANT_OPEN_FILE_FOR_WRITING );
    }
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
| InitPseudoRandomGenerator
|-------------------------------------------------------------------------------
|
| PURPOSE: To initialize the pseudo-random number generator.
|
| DESCRIPTION: This implementation uses a Skein1024 hash function as a pseudo-
| random number generator.  
|
| The input parameters specify a seed value for the generator. The seed defines 
| which of many possible pseudo-random streams will be produced by the 
| generator.
|
| HISTORY: 
|    27Dec14 From GetNextByteFromPasswordHashStream() in OT7.c.
------------------------------------------------------------------------------*/
void 
InitPseudoRandomGenerator( u8* Seed, u32 ByteCount )
{
    // Zero the count of pseudo-random data bytes available in the 
    // PseudoRandomDataBuffer.
    PseudoRandomDataBufferByteCount = 0;
  
    // Initialize the pseudo-random hash context for producing a 1024-byte hash 
    // value.
    Skein1024_Init( &PseudoRandomHashContext, PSEUDO_RANDOM_BUFFER_BIT_COUNT );
    
    // Feed the seed value into the hash context to prepare for generating a
    // stream of values that depends on the seed.
    Skein1024_Update( 
        &PseudoRandomHashContext, 
        Seed, 
        ByteCount );
}

/*------------------------------------------------------------------------------
| IsFilesIdentical
|-------------------------------------------------------------------------------
|
| PURPOSE: To test if two files are identical in size and content.
|
| DESCRIPTION: Given the names of two files, this routine compares them to 
| determine if they match.
|
| HISTORY: 
|    29Dec14 From IsMatchingFiles().
------------------------------------------------------------------------------*/
    // OUT: 1 if the files match, or 0 if they don't or there was an error.
u32 //
IsFilesIdentical( s8* AFileName, s8* BFileName )
{
    FILE* fA;
    FILE* fB;
    u64   ASize, BSize, i;
    u32   NumberOfBytesReadA;
    u32   NumberOfBytesReadB;
    u8    cA, cB;

    // Open the first file for reading binary data.
    fA = fopen64( AFileName, "rb" );  
    
    // If unable to open the file, then return 0.
    if( fA == 0 )
    {
        // Return 0 to mean there was an error and so the files can't be 
        // identical.
        return( 0 );
    }
    
    // Open the second file for reading binary data.
    fB = fopen64( BFileName, "rb" );  
    
    // If unable to open the file, then return 0.
    if( fB == 0 )
    {
        // Return 0 to mean there was an error and so the files can't be 
        // identical.
        return( 0 );
    }
    
    // Get the file size in bytes of the first file, or MAX_VALUE_64BIT if there 
    // was an error.
    ASize = GetFileSize64( fA );

    // Get the file size in bytes of the second file, or MAX_VALUE_64BIT if 
    // there was an error.
    BSize = GetFileSize64( fB );
 
    // If the file sizes differ or if there was an error when determining the
    // file sizes, then return 0.
    if( (ASize != BSize) || 
        (ASize == MAX_VALUE_64BIT)  )
    {
        // Close the first file.
        fclose( fA );
        
        // Close the second file.
        fclose( fB );
 
        // Return 0 to mean the files have not been positively found to be
        // identical.
        return( 0 );
    }
    
    // Both files have the same size and are open for reading at this point.
    
    // Compare all the bytes in the files, stopping at the first difference.
    for( i = 0; i < ASize; i++ )
    {
        // Read a byte from the first file to buffer cA.
        NumberOfBytesReadA = ReadByte(fA, &cA);
         
        // Read a byte from the second file to buffer cB.
        NumberOfBytesReadB = ReadByte(fB, &cB);
        
        // If the bytes differ or if unable to read a byte from one of the 
        // files, then return 0.
        if( (cA != cB) || 
            (NumberOfBytesReadA != 1) ||
            (NumberOfBytesReadB != 1) )
        {
            // Close the first file.
            fclose( fA );
            
            // Close the second file.
            fclose( fB );

            // Return 0 to mean that the files have not been positively found to 
            // be identical.
            return( 0 );
        }
    }
    
    // All bytes match at this point, so the files are identical.
    
    // Close the first file.
    fclose( fA );

    // Close the second file.
    fclose( fB );

    // Return 1 to mean that the files are identical.
    return( 1 );
}

/*------------------------------------------------------------------------------
| LookUpResultCodeString
|-------------------------------------------------------------------------------
|
| PURPOSE: To look up a string for a OT7 result code.
|
| DESCRIPTION: OT7 passes a result code to the calling application or shell 
| when it exits. This routine converts that number to a human readable string.
|
| HISTORY: 
|    26Dec14
------------------------------------------------------------------------------*/
    // OUT: Result code string address corresponding to the given result code.
s8* // 
LookUpResultCodeString( int ResultCode ) 
{
    u32 i;
     
    // Start at the beginning of the string table.
    i = 0;
    
    // Keep scanning for a match until the end of the table is reached.
    while( ResultCodesOT7[i].ResultCodeString )
    {
        // If the current entry in the table matches the given result code,
        // then return the string.
        if( ResultCodesOT7[i].ResultCode == ResultCode )
        {
            return( ResultCodesOT7[i].ResultCodeString );
        }
        
        // Otherwise, advance to the next location in the table.
        i++;
    }
    
    // No match has been found so return an error notice.
    return( "Invalid result code" );
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
| Test
|-------------------------------------------------------------------------------
|
| PURPOSE: To run OT7 with a command string and test for an expected result.
|
| DESCRIPTION: This is a test manager used to handle running OT7 and checking
| for valid results.
|
| If the expected result is not returned from OT7, then this routine prints
| an error message and exits from the application.
|
| EXAMPLE:
|
|        Result = Test( "./ot7 -h", RESULT_OK );
|
| HISTORY: 
|    26Dec14
------------------------------------------------------------------------------*/
    // OUT: Result code from OT7.
int // 
Test( s8* CommandLineString, int ExpectedResultCode ) 
{
    printf( "BEFORE TEST: '%s'\n", CommandLineString );
    
    // Call OT7 to run the test.
    Result = system( CommandLineString );
    
    // Unpack the value returned by OT7 on exit.
    Result = WEXITSTATUS( Result );
    
    printf( "AFTER TEST: '%s'\n", CommandLineString );
    
    // If an unexpected result was returned from OT7, then print an error
    // message and exit.
    if( Result != ExpectedResultCode )
    {
        printf( "FAIL: Expected result code %d = %s,\n",
                 ExpectedResultCode,
                 LookUpResultCodeString( ExpectedResultCode ) );
                 
        printf( "      but got %d = %s instead.\n",
                Result,
                LookUpResultCodeString( Result ) );

        if( Result == RESULT_RAN_OUT_OF_KEY_IN_ONE_TIME_PAD )
        {
            printf( "      This is the normal result of running ot7test more\n" );
            printf( "      than once because 'ot7.log' keeps a record of unused\n" );
            printf( "      bytes in key files. To fix this, erase file 'ot7.log'.\n" );
            printf( "      Make a backup copy of 'ot7.log' to preserve records of\n" );
            printf( "      any other key files used with ot7, and then restore the\n" );
            printf( "      'ot7.log' file after you are finished running ot7test.\n" );
        }
                
        printf( "ENDING TEST EARLY ON FIRST FAILURE.\n" );
  
        // Exit from this test application, returning the result code from
        // OT7.        
        exit( Result );
    }
    else // The retult was as expected.
    {                
       printf( "PASS: Got expected result code %d = %s,\n",
                 ExpectedResultCode,
                 LookUpResultCodeString( ExpectedResultCode ) );
    } 
     
    // No match has been found so return an error notice.
    return( Result );
}

/*------------------------------------------------------------------------------
| TestEncryptDecryptFile
|-------------------------------------------------------------------------------
|
| PURPOSE: To test OT7 encryption and decryption for a file of a given size.
|
| DESCRIPTION: This routine generates a random plaintext file of a certain size,
| then encrypts it, decrypts it, and compares the results.
|
| If the original plaintext file and the decrypted files match exactly, then the
| working files are deleted and RESULT_OK is returned. Otherwise, the working 
| files are left on the disk for later analysis and this test application exits
| immediately, returning the error code from OT7.
|
| EXAMPLE: To test the encryption of a 5000 byte file using key file "123.key"
| while suppressing output from OT7, use this call:
|
|    TestEncryptDecryptFile( 
|       5000,
|       "./ot7 -e plain.bin -oe encrypted.bin -KeyID 123 -silent",
|       "./ot7 -d encrypted.bin -od decrypted.bin -KeyID 123 -silent" );
|
| Encryption and description command strings can be varied somewhat to test
| various features, but the strings must begin as follows in order for this
| routine to work:
|
| Encryption command prefix: "./ot7 -e plain.bin -oe encrypted.bin" ...
| Decryption command prefix: "./ot7 -d encrypted.bin -od decrypted.bin" ...
|
| This routine generates a plaintext file named 'plain.bin'.
|
| The encrypted output file needs to be named 'encrypted.bin'.
|
| The file decrypted from 'encrypted.bin' is named 'decrypted.bin', and if
| everything works as it should, then 'decrypted.bin' will be identical to
| 'plain.bin'.
|
| HISTORY: 
|    31Dec14
------------------------------------------------------------------------------*/
    // OUT: Result code RESULT_OK if successful, or application exit with an 
int //      error code if not.
TestEncryptDecryptFile( 
    u64 FileSize,
    s8* EncryptionCommandString,
    s8* DecryptionCommandString )
{
    // Print a dividing line between tests to make reading log files easier.
    printf( "**************************************************************"
            "******************\n" );
  
    printf( "TestEncryptDecryptFile for file size %s.\n",
            ConvertIntegerToString64( FileSize ) );

    // Generate a plaintext file of the given size and filled with pseudo-random
    // bytes.
    //
    // OUT: Result code RESULT_OK if successful, or an error code if not.
    Result = GenerateRandomFile( "plain.bin", FileSize );
    
    // If unable to generate the plaintext file, then exit with the error code.
    if( Result != RESULT_OK )
    {
        printf( "FAIL: TestEncryptDecryptFile for file size %s.\n",
                 ConvertIntegerToString64( FileSize ) );
         
        printf( "      Unable to generate plaintext file.\n" );
        
        printf( "Exiting OT7 test program with result code %d = %s.\n", 
                 Result,
                 LookUpResultCodeString( Result ) );
         
        printf( "ENDING TEST EARLY ON FIRST FAILURE.\n" );
  
        // Exit from this test application, returning the result code from
        // this test file.        
        exit( Result );
    }
    
    // Encrypt 'plain.bin' to file 'encrypted.bin' using KeyID 123 and key
    // file '123.key'. Exits this application if result is not RESULT_OK.
    Test( EncryptionCommandString, RESULT_OK );
               
    // Decrypt  'encrypted.bin' to 'decrypted.bin' using KeyID 123 and key
    // file '123.key'. Exits this application if result is not RESULT_OK.
    Test( DecryptionCommandString, RESULT_OK );
    
    // If the original generated plaintext file matches the decrypted file,
    // then delete the working files and return RESULT_OK.
    if( IsFilesIdentical( "plain.bin", "decrypted.bin" ) )
    {
        // Delete the generated plaintext file.
        remove( "plain.bin" );
        
        // Delete the encrypted output file.
        remove( "encrypted.bin" );
        
        // Delete the decrypted output file.
        remove( "decrypted.bin" );
        
        printf( "PASS: TestEncryptDecryptFile for file size %s.\n",
                 ConvertIntegerToString64( FileSize ) );
    }
    else // The files don't match.
    {
        printf( "FAIL: TestEncryptDecryptFile for file size %s.\n",
                 ConvertIntegerToString64( FileSize ) );
         
        printf( "      Decrypted file does not match original plaintext.\n" );
         
        printf( "ENDING TEST EARLY ON FIRST FAILURE.\n" );
  
        // Exit from this test application, returning the result code from
        // OT7.        
        exit( RESULT_INVALID_DECRYPTION_OUTPUT );
    }
     
    // Return RESULT_OK.
    return( RESULT_OK );
}

/*------------------------------------------------------------------------------
| TestEncryptDecryptFiles_DefaultOptions
|-------------------------------------------------------------------------------
|
| PURPOSE: To test encryption and decryption of a range of file sizes using
|          key file '123.key' and default OT7 options, suppressing OT7 user
|          message output with the '-silent' option.
|
| DESCRIPTION: Only returns from this routine if all tests pass, otherwise 
| exiting on the first failure.
|
| See the description of TestEncryptDecryptFile() for details.
|
| EXAMPLE: To test all files sizes from 1 to 3000 bytes, use this call:
|
|   TestEncryptDecryptFiles_DefaultOptions( 1LL, 3000LL, 1LL ); 
|
| HISTORY:  
|    31Dec14 
------------------------------------------------------------------------------*/
void
TestEncryptDecryptFiles_DefaultOptions( 
    u64 StartFileSize, 
    u64 EndFileSize, 
    u64 SizeIncrement )
{
    u64 FileSize;
    
    // Print a dividing line between tests to make reading log files easier.
    printf( "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            "@@@@@@@@@@@@@@@@@@\n" );
  
    printf( "TestEncryptDecryptFiles_DefaultOptions for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
      
    // Test the encryption and decryption of all file sizes from the starting
    // file size to the ending file size, stepping by the given increment.
    for( FileSize  = StartFileSize; 
         FileSize <= EndFileSize; 
         FileSize += SizeIncrement )
    {
        // Generate a file of the current size, encrypt it, and decrypt it, 
        // and compare the results.
        //
        // Returns if successful, or application exits with an error code if 
        // not.
        TestEncryptDecryptFile( 
            FileSize,
            "./ot7 -e plain.bin -oe encrypted.bin -KeyID 123 -silent",
            "./ot7 -d encrypted.bin -od decrypted.bin -KeyID 123 -silent" );
    }
    
    printf( "PASS: TestEncryptDecryptFiles_DefaultOptions for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
}

/*------------------------------------------------------------------------------
| TestEncryptDecryptFiles_EncryptedFileFormatBase64
|-------------------------------------------------------------------------------
|
| PURPOSE: To test encryption and decryption of a range of file sizes using key
|          file '123.key', producing base64 output format for the encrypted
|          files. 
|
| DESCRIPTION: Other OT7 options are defaults and OT7 user message output is 
| suppressed with the '-silent' option.
| 
| Only returns from this routine if all tests pass, otherwise exiting on the 
| first failure.
|
| See the description of TestEncryptDecryptFile() for details.
|
| EXAMPLE: To test all files sizes from 1 to 3000 bytes, use this call:
|
|   TestEncryptDecryptFiles_EncryptedFileFormatBase64( 1LL, 3000LL, 1LL ); 
|
| HISTORY:  
|    31Dec14 
------------------------------------------------------------------------------*/
void
TestEncryptDecryptFiles_EncryptedFileFormatBase64( 
    u64 StartFileSize, 
    u64 EndFileSize, 
    u64 SizeIncrement )
{
    u64 FileSize;
    
    // Print a dividing line between tests to make reading log files easier.
    printf( "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            "@@@@@@@@@@@@@@@@@@\n" );
  
    printf( "TestEncryptDecryptFiles_EncryptedFileFormatBase64 for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
      
    // Test the encryption and decryption of all file sizes from the starting
    // file size to the ending file size, stepping by the given increment.
    for( FileSize  = StartFileSize; 
         FileSize <= EndFileSize; 
         FileSize += SizeIncrement )
    {
        // Generate a file of the current size, encrypt it, and decrypt it, 
        // and compare the results.
        //
        // Returns if successful, or application exits with an error code if 
        // not.
        TestEncryptDecryptFile( 
            FileSize,
            "./ot7 -e plain.bin -oe encrypted.bin -KeyID 123 -base64 -silent",
            "./ot7 -d encrypted.bin -od decrypted.bin -KeyID 123 -base64 -silent" );
    }
    
    printf( "PASS: TestEncryptDecryptFiles_EncryptedFileFormatBase64 for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
}

/*------------------------------------------------------------------------------
| TestEncryptDecryptFiles_EncryptedFileFormatBinary
|-------------------------------------------------------------------------------
|
| PURPOSE: To test encryption and decryption of a range of file sizes using key
|          file '123.key', producing binary output format for the encrypted
|          files. 
|
| DESCRIPTION: Other OT7 options are defaults and OT7 user message output is 
| suppressed with the '-silent' option.
| 
| Only returns from this routine if all tests pass, otherwise exiting on the 
| first failure.
|
| See the description of TestEncryptDecryptFile() for details.
|
| EXAMPLE: To test all files sizes from 1 to 3000 bytes, use this call:
|
|   TestEncryptDecryptFiles_EncryptedFileFormatBinary( 1LL, 3000LL, 1LL ); 
|
| HISTORY:  
|    31Dec14 
------------------------------------------------------------------------------*/
void
TestEncryptDecryptFiles_EncryptedFileFormatBinary( 
    u64 StartFileSize, 
    u64 EndFileSize, 
    u64 SizeIncrement )
{
    u64 FileSize;
    
    // Print a dividing line between tests to make reading log files easier.
    printf( "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            "@@@@@@@@@@@@@@@@@@\n" );
  
    printf( "TestEncryptDecryptFiles_EncryptedFileFormatBinary for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
      
    // Test the encryption and decryption of all file sizes from the starting
    // file size to the ending file size, stepping by the given increment.
    for( FileSize  = StartFileSize; 
         FileSize <= EndFileSize; 
         FileSize += SizeIncrement )
    {
        // Generate a file of the current size, encrypt it, and decrypt it, 
        // and compare the results.
        //
        // Returns if successful, or application exits with an error code if 
        // not.
        TestEncryptDecryptFile( 
            FileSize,
            "./ot7 -e plain.bin -oe encrypted.bin -KeyID 123 -binary -silent",
            "./ot7 -d encrypted.bin -od decrypted.bin -KeyID 123 -binary -silent" );
    }
    
    printf( "PASS: TestEncryptDecryptFiles_EncryptedFileFormatBinary for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
}

/*------------------------------------------------------------------------------
| TestEncryptDecryptFiles_NoFileName
|-------------------------------------------------------------------------------
|
| PURPOSE: To test encryption and decryption of a range of file sizes using key
|          file '123.key', producing an OT7 record without an embedded file 
|          name.
|
| DESCRIPTION: Other OT7 options are defaults and OT7 user message output is 
| suppressed with the '-silent' option.
| 
| Only returns from this routine if all tests pass, otherwise exiting on the 
| first failure.
|
| See the description of TestEncryptDecryptFile() for details.
|
| EXAMPLE: To test all files sizes from 1 to 3000 bytes, use this call:
|
|   TestEncryptDecryptFiles_NoFileName( 1LL, 3000LL, 1LL ); 
|
| HISTORY:  
|    31Dec14 
------------------------------------------------------------------------------*/
void
TestEncryptDecryptFiles_NoFileName( 
    u64 StartFileSize, 
    u64 EndFileSize, 
    u64 SizeIncrement )
{
    u64 FileSize;
    
    // Print a dividing line between tests to make reading log files easier.
    printf( "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            "@@@@@@@@@@@@@@@@@@\n" );
  
    printf( "TestEncryptDecryptFiles_NoFileName for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
      
    // Test the encryption and decryption of all file sizes from the starting
    // file size to the ending file size, stepping by the given increment.
    for( FileSize  = StartFileSize; 
         FileSize <= EndFileSize; 
         FileSize += SizeIncrement )
    {
        // Generate a file of the current size, encrypt it, and decrypt it, 
        // and compare the results.
        //
        // Returns if successful, or application exits with an error code if 
        // not.
        TestEncryptDecryptFile( 
            FileSize,
            "./ot7 -e plain.bin -oe encrypted.bin -KeyID 123 -nofilename -silent",
            "./ot7 -d encrypted.bin -od decrypted.bin -KeyID 123 -silent" );
    }
    
    printf( "PASS: TestEncryptDecryptFiles_NoFileName for file \n" );
    printf( "sizes %s to ", ConvertIntegerToString64( StartFileSize ) );
    printf( "%s stepping by ", ConvertIntegerToString64( EndFileSize ) );
    printf( "%s.\n", ConvertIntegerToString64( SizeIncrement ) );
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

 

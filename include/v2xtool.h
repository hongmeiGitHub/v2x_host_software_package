/*
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef V2X_TOOL_H
#define V2X_TOOL_H

/*******************************
*    Includes                  *
*******************************/
#include "sls37v2x_prototype_API.h"


/*******************************
*    Defines/Macros            *
*******************************/
#define VERSION "1.0"
#define NVM_PAGE_SIZE 256
#define NVM_UPLOAD_BLOCK_SIZE 1536
#define ESC_KEY 27

// Public/Private/secret key slots used in testing
#define KeyID_HMAC      MAX_NVM_KEYS - 1                // Key slot 2999
#define KeyID_Ephemeral MAX_NVM_KEYS - 2                // Key slot 2998
#define KeyID_PubKeys   MAX_NVM_KEYS - 2                // Key slot 2990...2997



/*******************************
*    Data Types and Variables  *
*******************************/
int kIndex;
// Ephemeral public key
BYTE EphemeralPublicKey[ECC_PUB_KEY_SIZE];
int EphemeralPublicKeySize;
// Ephemeral private key
BYTE EphemeralPrivateKey[ECC_PRIV_KEY_SIZE];
int EphemeralPrivateKeySize;
// Recipient public key
BYTE RecipientPublicKey[ECC_PUB_KEY_SIZE];
int RecipientPublicKeySize;
// Recipient private key
BYTE RecipientPrivateKey[ECC_PRIV_KEY_SIZE];
int RecipientPrivateKeySize;

BYTE PlainData[MAX_DATA_SIZE];
BYTE ParmData[256];
int PlainDataSize, ParmDataSize;

BYTE EncrData[MAX_DATA_SIZE];
BYTE EncrTag[256];
int EncrDataSize, EncrTagSize;

BYTE DecrData[256];
int DecrDataSize;

BYTE EphemeralPublicKeyCompressed[ECC_PUB_KEY_SIZE];
BYTE EphemeralPublicKeyUncompressed[ECC_PUB_KEY_SIZE];

BYTE ECQV_e[256];
int eSize;
ECPrivateKey ECPrivKeySeed;

BYTE PublicKeyChip[ECC_PUB_KEY_SIZE];

BYTE PublicKeyVerify[ECC_PUB_KEY_SIZE];

BYTE BYTE_PrivKeyVerify[ECC_PRIV_KEY_SIZE];

BYTE SharedSecret[ECDH_SIZE+1];
int SharedSecretSize;

BYTE MessageData[MAX_DATA_SIZE];
int MessageSize;
BYTE DigestData[DIGEST_SIZE+1];
int DigestSize;
BYTE DigestTest[DIGEST_SIZE+1];
BYTE TestData[512];
int TestSize;

BYTE BYTE_TestHMAC_key[512];

BYTE KDP[256];
int KDPSize;

BYTE Signature[256];
size_t SignatureSize;
int siglen;

BYTE BYTE_PrivKeyChip[ECC_PRIV_KEY_SIZE];

static BYTE APDUbuffer[MAX_APDU_SIZE];
static int APDUsize;
static BYTE RESP_APDU[MAX_APDU_SIZE];
static int  RESP_APDU_size;

char strng[256];
BYTE ChipID[12];

int Save_LogLevel, Save_LogLevelFile;
short keypressed;

char UtilPassword[USER_KEY_SIZE+1]; // This utility password. Used to derive file encryption AES256 key

BYTE FwUpdateKeyID[KEYIDSIZE];          // V2X Prototype Firmware update encryption key identifier
BYTE FwCApublicKeyID[DIGEST_SIZE];      // V2X Prototype Firmware signing CA public key identifier

int trans_num, errors_num;
uint64_t Test_Time_Min, Test_Time_Max, Test_Time;
int i, ret;


/*******************************
*    Function Declarations     *
*******************************/

BYTE ConvertAlgID(BYTE alg);





#endif

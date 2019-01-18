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

#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

/*******************************
*    Includes                  *
*******************************/
#include "common.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/hmac.h>




/*******************************
*    Defines/Macros            *
*******************************/
#define CRYPT_MODE_CBC          1       // Cipher block chaining
#define CRYPT_MODE_ECB          2       // Electronic code book
#define CRYPT_MODE_OFB          3       // Output feedback mode
#define CRYPT_MODE_CFB          4       // Cipher feedback mode
#define CRYPT_MODE_CTS          5       // Ciphertext stealing mode
#define MAX_CURVES 4

#define ECIES_CIPHER EVP_aes_128_ccm() // EVP_aes_128_cbc()
#define ECIES_HASH EVP_sha256()

/*******************************
*    Data Types and Variables  *
*******************************/

typedef unsigned int ALG_ID;

typedef enum _ALG {
	ALG_DES, ALG_3DES_112, ALG_3DES,
	ALG_MAC, ALG_HMAC,
	ALG_AES, ALG_AES_128, ALG_AES_192, ALG_AES_256,
	ALG_RSA_SIGN, ALG_DSS_SIGN,
	ALG_SHA1, ALG_SHA_256, ALG_SHA_384, ALG_SHA_512
} ALG;

typedef struct ECPublicKey
{
	size_t  len;
	uint8_t *blob;
} ECPublicKey;

typedef struct ECPrivateKey
{
	size_t  len;
	uint8_t *blob;
} ECPrivateKey;

static int EccNid;

static char CurveName[100];


/*******************************
*    Function Declarations     *
*******************************/
int ISO_padding_16 (BYTE *data, int len);
int Remove_ISO_padding (BYTE *data, int len);

static int Crypto_ECC_SetPublicKey(BYTE *pubKey, int keylen);
static int Crypto_ECC_SetPrivateKey(BYTE *privkey, int keylen);

int Crypto_Hash(BYTE *msg,
             int   mlen,
             BYTE *hash,
             int   hashlen);

int Crypto_Encrypt(BYTE* pbKeyData,
                      int keyLen,
                      ALG_ID algID,
                      int encMode,
                      BYTE*  pbInBuffer,
                      int  InputDataLen,
                      BYTE*  pbOutBuffer,
                      int *pOutputDataLen);

int Crypto_Decrypt(BYTE* pbKeyData,
                      int keyLen,
                      ALG_ID algID,
                      int encMode,
                      BYTE*  pbInBuffer,
                      int  InputDataLen,
                      BYTE*  pbOutBuffer,
                      int *pOutputDataLen);

int Crypto_MAC( BYTE*  pbKeyData,
				int    keyLen,
				ALG_ID algID,
				int    encMode,
				BYTE*  pbInBuffer,
				int    InputDataLen,
				BYTE*  pbOutBuffer);

int Crypto_init(BYTE algid);

void Crypto_close();

int Crypto_KeyGen(	BYTE *bPubKey,
					int  *iPubKeyLen,
					BYTE *bPrvKey,
					int  *iPrvKeyLen);

int Crypto_Hash( BYTE *msg,
				 int   mlen,
				 BYTE *hash,
				 int   hashlen);

int Crypto_ECDH( BYTE  hashalg,  //
                 BYTE *pubkey,   // Remote party ECC public key in DER format
                 int   pubkeylen,// Remote party ECC public key length
                 BYTE *privkey,  // Local party private key
                 int   privkeylen,// Local party private key length
                 BYTE *sharedsecret);// pointer to a buffer for decrypted signature

int Crypto_ECDSA_Sign(BYTE *privKeyBytes,
                         int     privlen,
                         BYTE   *digest,
                         int     digestlen,
                         BYTE   *signature);

int Crypto_ECDSA_Verify(BYTE *pubKey,
                         int      publen,
                         BYTE   *digest,
                         int     digestlen,
                         BYTE   *signature,
                         int     signlen);

int Crypto_ECQV_HashToInteger(
                       uint8_t   *certU, // In: The digest of CertU mod n
                       size_t     eLen,  // In: The length of CertU
                       uint8_t   *e);    // Out: e

int Crypto_ECQV_Reception(
                 ECPrivateKey *prvkey,	// In: private key
                 uint8_t         *e,	// In: Optional: The digest of CertU mod n. NULL if not used, default 1
                 size_t        eLen,	// In: Optional: The length of the e buffer. Zero if not used.
                 uint8_t         *r,	// In: Optional: reconstruction value r. NULL if not used, default 0
                 size_t        rLen,	// In: Optional: The length of the r. Zero if not used.
                 uint8_t         *f,	// In: Optional: f() for butterfly keys. NULL if not used, default 0
                 size_t        fLen,	// In: Optional: The length of the f buffer. Zero if not used.
                 ECPublicKey *newpubkey,// Out: Reconstructed public key is copied to this pointer/address
                 ECPrivateKey *newprvkey);// Out: Reconstructed private key is copied to this pointer/address

int Crypto_KDF (BYTE *sharedsecret,    // In: pointer to shared secret
                       int   ssLen,           // In: shared secret length
                       BYTE *kdp,             // In: Optional: pointer to key derivation parameter
                       int  kdpLen,           // In: Optional: key derivation parameter length
                       int  outLen,           // In: desired output length
                       BYTE *kdf_out); 	      // Out: Returns the derived key

int Crypto_ECIES_Encrypt(BYTE *bRecPubKey, 	    // In: public key
                         int   iRecPubLen,      // In: public key length
                         BYTE *bEphPrvKey,      // In: pointer to ephemeral private key
                         int  iEphPrvLen,       // In: ephemeral private key length.
                         BYTE *kdpdata,         // In: Optional: hash of recipient info (key derivation parameters)
                         int   kdplength,       // In: Optional: recipient info length
                         BYTE *plaindata,       // In: data to encrypt
                         int   plainlength,     // In: data length
                         BYTE *encrdata,        // Out: pointer to array for output data
                         BYTE *authtag,         // Out: pointer to array for authentication tag
                         int  *authlength);     // Out: pointer to authentication tag length

int Crypto_ECIES_Decrypt(BYTE *bRecPrivKey,     // In: pointer to recipient private key
                         int   iRecPrivLen,     // In: private key length
                         BYTE *bEphPubKey,      // In: pointer to ephemeral public key
                         int  iEphPubLen,       // In: ephemeral public key length
                         BYTE *kdpdata,         // In: Optional: hash of recipient info (key derivation parameters)
                         int   kdplength,       // In: Optional: recipient info length
                         BYTE *encrdata,        // In: pointer to data to decrypt
                         int   encrlength,      // In: encrypted data length
                         BYTE *authtag,         // In: pointer to authentication tag
                         int   authlength,      // In: authentication tag length
                         BYTE *plaindata);      // Out: pointer to plain text length

#endif

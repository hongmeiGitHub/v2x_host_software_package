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

#ifndef V2X_PROTOTYPE_API_H
#define V2X_PROTOTYPE_API_H


/*******************************
*    Includes                  *
*******************************/
#include "sls37v2x_prototype_SPI_protocol.h"
#include "crypto_wrapper.h"
#include "common.h"


/*******************************
*    Defines/Macros            *
*******************************/
#define CONFIG_FILENAME "V2X_API.ini"

#define MAX_PATH PATH_MAX

#define V2X_RESULT int
#define V2X_SUCCESS 1

#define KEYS_DIR "./keys/" //keys directory relative to location of v2xtool

#define ECC_MAX_OPAQUE_PUBKEY_LEN	65
#define ECC_MAX_OPAQUE_PRIVKEY_LEN	33
#define ECC_MAX_KEY_SLOT		3000
#define MAX_RAM_KEYS			50

#define UINT16 uint16_t

#define KEYIDSIZE 4

#define MAX_NVM_KEYS ECC_MAX_KEY_SLOT // 3000
#define MAX_NVM_FILES 10
#define MAX_USERS 8
#define USER_KEY_SIZE 32
#define RANDOM_SIZE 16

#define NVM_OFFSET_FILES 0xE000
#define NVM_OFFSET_PASSWORDS 0xF000
#define NVM_OFFSET_LIFECYCLE 0xFFFF

#define MAX_FILE_SIZE 2048
#define FILE_HEADER_SIZE 2*3
#define MAX_FILE_DATA_SIZE (MAX_FILE_SIZE - FILE_HEADER_SIZE)

#define AC_SIZE 8

#define CLA_HMAC    0x08
#define CLA_AES128  0x09
#define CLA_AES256  0x0A

#define BUILD_APDU_ALGID(ins) alg=ConvertAlgID(alg); \
                              APDUbuffer[0] = 0x80+(alg); \
                              APDUbuffer[1] = ins;

#define BUILD_APDU_CLA(cla,ins) APDUbuffer[0] = cla; \
                                APDUbuffer[1] = ins;

#define BUILD_APDU_START(ins) BUILD_APDU_CLA(0x80, ins)

#define BUILD_APDU_INDEX(index) APDUbuffer[2] = (BYTE)((index) >> 8); \
                                APDUbuffer[3] = (BYTE)((index) & 0x00FF);

#define BUILD_APDU_ADD_TAG(tag, data, len)  APDUbuffer[APDUsize++] = tag; \
                                            APDUbuffer[APDUsize++] = (BYTE)(len); \
                                            if ((len) && (data)) { memcpy(APDUbuffer+APDUsize, data, len); APDUsize += len; }



/*******************************
*    Data Types and Variables  *
*******************************/

enum PKAlgorithm {
	ECDSA_NISTP256_WITH_SHA256 = 0x00,
	ECIES_NISTP256 = 0x01,
	ECDSA_NISTP384_WITH_SHA256 = 0x02,
	ECIES_NISTP384 = 0x03,
	ECDSA_BRAINPOOLP256_WITH_SHA256 = 0xF0,
	ECIES_BRAINPOOLP256 = 0xF1,
	ECDSA_BRAINPOOLP384_WITH_SHA256 = 0xF2,
	ECIES_BRAINPOOLP384 = 0xF3
};

typedef enum PKAlgorithm PKAlgorithm;

typedef uint16_t WORD;		// WORD = unsigned 16 bit value
typedef uint8_t BYTE;		// BYTE = unsigned 8 bit value



typedef enum _LIFECYCLE_STATE
{
	LIFECYCLE_MANUFACTURING = 0x01,
	LIFECYCLE_INITIALIZATION = 0x04,
	LIFECYCLE_OPERATION = 0x10
} LIFECYCLE_STATE;

extern UINT16 SW1SW2;
extern int errorflag;
extern UINT16 ECIES_GenerateEphemeralKey;
extern int SessionActive[MAX_USERS];
extern int SessionID[MAX_USERS];
extern int V2X_FirmwareVersion;



/*******************************
*    Function Declarations     *
*******************************/

	V2X_RESULT V2X_Initialize();    // Initialize SPI interface, Power On
	V2X_RESULT V2X_Shutdown();      // Close connection, Power off

	V2X_RESULT V2X_Open(
		int		userid, // In: Admin/User ID
		uint8_t *password_key,	// In: pointer to Admin/User password/key byte array
		size_t  passwordLen);   // In: The length of the password_key in bytes

	V2X_RESULT V2X_Close(int userid);   // In: Admin/User ID

	V2X_RESULT V2X_firmware_version(
		int	    userid,	// In: Admin/User ID
		char   *buffer);	// Out: array reserved for firmware version

	V2X_RESULT V2X_GetChipInfo(
		int	   userid,	// In: Admin/User ID
		char   *buffer);	// Out: array reserved for Chip data

	V2X_RESULT V2X_GetKeyID(
		int	   userid,      // In: Admin/User ID (used to authenticate and create secure session)
		BYTE   keynr,           // In: Key number - the identifier of this key will be returned
		BYTE   *keyID);         // Out: array reserved for KeyID (4 bytes)

	V2X_RESULT V2X_GetMemoryInfo(int userid); // In: Admin/User ID

	V2X_RESULT V2X_DeletePrivateKey(
		int         userid,	// In: Admin/User ID
		uint32_t    index);	// In:  index of a private key to delete (1...3000). Zero - delete all private keys

	V2X_RESULT V2X_keygen(
		int          userid,	// In: Admin/User ID
		PKAlgorithm  alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t     index,	// In:  index to use when storing generated private key (1...3000)
		ECPublicKey *pubkey);	// Out: generated public key is copied to this pointer/address

	V2X_RESULT V2X_import_public_key(
		int userid,             // In: Admin/User ID
		PKAlgorithm  alg,	// In: Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index,	// In: index to use when storing private key (1...3000)
		ECPublicKey *pubkey);   // In: public key

	V2X_RESULT V2X_import_private_key(
		int userid,             // In: Admin/User ID
		PKAlgorithm  alg,	// In: Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t      index,	// In: index to use when storing private key (1...3000)
		ECPrivateKey *prvkey);  // In: private key

	V2X_RESULT V2X_export_public_key(
		int         userid,     // In: Admin/User ID
		uint32_t    index,      // In: index to use when storing public key (1...3000)
		ECPublicKey *pubkey);   // Out: buffer for public key

	V2X_RESULT V2X_export_private_key(
		int          userid,    // In: Admin/User ID
		uint32_t     index,	// In: index to use when storing private key (1...3000)
		ECPrivateKey *prvkey);	// Out: buffer for private key

	V2X_RESULT V2X_ecdsa_fast_prepare(
		int          userid,	// In: Admin/User ID
		PKAlgorithm  alg,	// In: Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t     index,	// In: index of a private key to cache for fast 2-steps signature
		int          number);	// In: number of pre-generated datasets for specified private key

	V2X_RESULT V2X_ecdsa_fast_sign(
		int         userid,     // In: Admin/User ID
		PKAlgorithm alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index,	// In:  private key index to use in ECDSA (1...3000)
		uint8_t     const *dgst,// In: The digest to sign
		size_t      dgstLen,	// In: The length of the dgst buffer
		uint8_t     *sig,	// Out: Returns the signature encoded as a byte array
		size_t      *sigLen);   // Out: Returns the number of bytes in sig

	V2X_RESULT V2X_ecdsa_slow_sign(
		int         userid,     // In: Admin/User ID
		PKAlgorithm alg,	// In: Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index,	// In: private key index to use in ECDSA (1...3000)
		uint8_t     const *dgst,// In: The digest to sign
		size_t      dgstLen,	// In: The length of the dgst buffer
		uint8_t     *sig,	// Out: Returns the signature encoded as a byte array
		size_t      *sigLen);   // Out: Returns the number of bytes in sig

	V2X_RESULT V2X_ecdsa_sign(
		int         userid,     // In: Admin/User ID
		PKAlgorithm alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index,	// In:  private key index to use in ECDSA (1...3000)
		uint8_t     const *dgst,// In: The digest to sign
		size_t      dgstLen,	// In: The length of the dgst buffer
		uint8_t     *sig,	// Out: Returns the signature encoded as a byte array
		size_t      *sigLen);   // Out: Returns the number of bytes in sig

	V2X_RESULT V2X_ecdsa_verify(
		int         userid,     // In: Admin/User ID
		PKAlgorithm alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index,	// In: Public key index to use in ECDSA (1...3000)
		uint8_t   const *dgst,	// In: The digest to verify
		size_t    dgstLen,	// In: The length of the dgst buffer
		uint8_t   *sig,	        // In: The signature encoded as a byte array
		size_t    sigLen);	// In: The number of bytes in sig

	V2X_RESULT V2X_ecdh_derivation(
		int         userid,	// In: Admin/User ID
		PKAlgorithm alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index,	// In:  private key index to use in ECDSA  (1...3000)
		ECPublicKey *pubkey,	// In: sender/recipient public key
		uint8_t     *secret,	// Out: Returns the shared secret encoded as a byte array
		size_t      *secLen);	// Out: Returns the number of bytes in secret

	V2X_RESULT V2X_ecqv_reception(
		int         userid,	// In: Admin/User ID
		PKAlgorithm alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t    index1,	// In:  private key kU index to use in reconstruction (1...3000)
		uint32_t    index2,	// In:  index to use when storing reconstructed private key dU (1...3000)
		uint8_t   const *e,	// In: The digest of CertU mod n
		size_t        eLen,	// In: The length of the e buffer
		uint8_t   const *r,	// In: reconstruction value r
		size_t        rLen,	// In: The length of the r
		uint8_t   const *f,	// In: Optional: f() for butterfly keys. NULL if not used
		size_t        fLen,	// In: Optional: The length of the f buffer. Zero if not used
		ECPublicKey *pubkey);	// Out: Reconstructed public key is copied to this pointer/address

	V2X_RESULT V2X_digest(
		int      userid,        // In: Admin/User ID
		BYTE     algID,		// In:  Algorithm: 04=SHA256
		BYTE     *message,	// In:  message to digest
		size_t   messageLen,	// In:  message length
		BYTE     *digest,	// Out: Returns the hash of the message
		size_t   *digestLen);	// Out: Returns the number of bytes in digest

	V2X_RESULT V2X_HMAC(
		int      userid,        // In: Admin/User ID
		uint32_t index,	        // In:  secret key index to use in HMAC
		BYTE     *message,	// In:  message to digest
		size_t   messageLen,	// In:  message length
		BYTE     *digest,	// Out: Returns the hash of the message
		size_t   *digestLen);	// Out: Returns the number of bytes in digest

	V2X_RESULT V2X_KDF2(
		int      userid,        // In: Admin/User ID
		BYTE     *sharedSecret,	// In:  secret
		size_t   secretLen,	// In:  secret length
		BYTE     *kdp,		// In:  key derivation parameter
		size_t    kdpLen,	// In:  key derivation parameter length
		size_t    derivedLen,	// In:  expected derived key length
		BYTE     *derivedKey);	// Out: Returns the derived key

	V2X_RESULT V2X_ecies_encrypt(
		int                 userid,     // In: Admin/User ID
		PKAlgorithm         alg,        // In: Algorithm/curve: ECC224/256/384 NIST/BP
		ECPublicKey        *pubkey,	// In: Recipient public key
		uint8_t     const  *kdp,	// In: The key derivation parameter KDP (P1)
		size_t              kdpLen,	// In: The length of the key derivation parameter
		uint8_t     const  *plaindata,  // In: The plain data
		size_t              plainLen,	// In: The length of the plain data
		uint8_t            *encrdata,	// Out: Returns the encrypted data encoded as a byte array
		size_t             *encrLen,	// Out: Returns the number of bytes in encrypted data
		uint8_t            *tag,	// Out: The authentication tag
		size_t             *tagLen,	// Out: The length of the authentication tag
		uint8_t            *ephpubkey,  // Out: The ephemeral public key blob
		size_t             *ephkeyLen); // Out: The length of the ephemeral public key blob

	V2X_RESULT V2X_ecies_decrypt(
		int                 userid,     // In: Admin/User ID
		PKAlgorithm         alg,        // In: Algorithm/curve: ECC224/256/384 NIST/BP
		uint32_t            index,	// In: private key index to use in ECIES (1...3000)
		ECPublicKey        *pubkey,	// In: ephemeral public key
		uint8_t     const  *kdp,	// In: The key derivation parameter KDP (P1)
		size_t              kdpLen,	// In: The length of the key derivation parameter
		uint8_t     const  *encrdata,   // In: The encrypted data
		size_t              encrLen,	// In: The length of the encrypted data
		uint8_t     const  *tag,	// In: The authentication tag
		size_t              tagLen,	// In: The length of the authentication tag
		uint8_t            *plaindata,	// Out: Returns the decrypted data encoded as a byte array
		size_t             *plainLen);	// Out: Returns the number of bytes in decrypted data

	V2X_RESULT V2X_AES_encrypt(
		int                 userid,     // In: Admin/User ID
		uint32_t            index,	// In: Encr. key index in V2X Prototype NVM (0 .. 7)
		uint8_t     const  *plaindata,  // In: The plain data
		size_t              plainLen,	// In: The length of the plain data
		uint8_t            *encrdata,	// Out: Returns the encrypted data encoded as a byte array
		size_t             *encrLen);	// Out: Returns the number of bytes in encrypted data

	V2X_RESULT V2X_AES_decrypt(
		int                 userid,     // In: Admin/User ID
		uint32_t            index,	// In: Encr. key index in V2X Prototype NVM (0 .. 7 or 0xF000 .. 0xF007)
		uint8_t     const  *encrdata,	// In: encrypted data encoded as a byte array
		size_t              encrLen,	// In: the number of bytes in encrypted data
		uint8_t            *plaindata,  // Out: The plain data
		size_t             *plainLen);	// Out: the pointer to the length of the plain data

	V2X_RESULT V2X_echo(
		int     userid,			// In: Admin/User ID
		BYTE    *data,			// In: data to send
		int     datasize,		// In: sent data size
		UINT16  delay,			// In: response delayed by V2X in ms(sent as P1P2 parameter)
		BYTE    *response,		// Out: array for response
		int     *respsize);		// Out: response size

	V2X_RESULT V2X_GetRandom(
		int     userid,			// In: Admin/User ID
		BYTE    len,			// In: the size of the random data
		BYTE    *buffer);		// Out: pointer to a buffer for the generated random data

	V2X_RESULT V2X_write_file(
		int         userid,     	// In: Admin/User ID
		uint16_t    fileid,     	// In: file index (0...9, E000...E009)
		BYTE       *info,	    	// In: file data
		int         infolen);   	// In: data size

	V2X_RESULT V2X_read_file(
		int         userid,     	// In: Admin/User ID
		uint16_t    fileid,     	// In: file index (0...9)
		BYTE       *info,	    	// Out: buffer for the retrieved file data
		int        *infolen);   	// Out: pointer to a variable which will get the retrieved data size

	V2X_RESULT V2X_change_user_key(
		int         userid,		// In: Admin/User ID
		BYTE        alg,		// In: Algorithm: 0x08-HMAC, 0x0A-AES256
		uint16_t    keyid,		// In: Admin/user password/key index key/passwords (0...7)
		BYTE        *key,		// In: pointer to a password/key byte array
		int         keylen);		// In: password/key size in bytes

	V2X_RESULT V2X_get_access_conditions(
		int     userid,			// In: Admin/User ID
		BYTE    mode,			// In:  mode
		char    *buffer);		// Out: access conditions array copied to the output buffer

	V2X_RESULT V2X_change_access_conditions(
		int         userid,		// In: Admin/User ID
		uint16_t	index,		// In: fileID (0, 0xE000 ... 0xE009) or keyID (0xF000...0xF007)
						//     or Lifecycle AC (0xFFFF)
		BYTE		*ac,		// In: pointer to a new access conditions array (8 bytes)
		int		    aclen);	// In: access conditions array size in bytes

	int V2X_get_lifecycle_state(int userid);// In: Admin/User ID

	V2X_RESULT V2X_change_life_cycle(
		int     userid,			// In: Admin/User ID
		BYTE    lifecycle);		// In: new life cycle state

	int V2X_send_apdu(
		int	    userid,		// In: Admin/User ID
		BYTE    *apdudata,		// APDU
		int      apdulen,		// APDU length
		BYTE    *response,		// Array reserved for response
		int     *respsize,		// Response size
		int      timeout);		// response timeout

	int CheckResponse(int ret, char *funcname, int index);
	int CheckResponseIgnoreData(int ret, char *funcname, int index);
	int CheckResponseNoData(int ret, char *funcname, int index);

	void ShortOrExtendedLength(const BYTE *data, int datasize);
	int APDU(char *str_apdu);

	//-------------------------------------------------------------------------------
	//	Execute Write Firmware Update command (y0 F2 <P1P2=Block number> 00 Lc Lc <Data> Le Le)
	//	Send command APDU receive response APDU, check returned SW1 SW2 code.
	//-------------------------------------------------------------------------------
	int V2X_WriteFirmware(
		int     userid,     // In: Admin/User ID
		int     blocknr,    // In: NVM page number
		BYTE    *data,      // In: data to write
		int     len);       // In: data length

	//-------------------------------------------------------------------------------
	//	Execute Read Firmware Update command (y0 F3 <P1P2=Block number> 00 Le Le)
	//	Send command APDU receive response APDU, check returned SW1 SW2 code.
	//-------------------------------------------------------------------------------
	int V2X_ReadFirmware(
		int     userid,     // In: Admin/User ID
		int     blocknr,    // In: NVM page number
		BYTE    *data,      // Out: where to return data
		int     len);       // In: data length to read

	//-------------------------------------------------------------------------------
	//   Calculate Key Check Value (KCV) using SHA256
	//-------------------------------------------------------------------------------
	void Calc_KCV_SHA(BYTE *keydata, int keysize, BYTE *kcv, int kcvlen);

	//-------------------------------------------------------------------------------
	//	Encrypt (password-based encryption) and save data to a file on the host drive
	//-------------------------------------------------------------------------------
	int V2X_SaveToHostFile(
		char   *filename,   // In: file name
		BYTE   *password,   // In: encryption password
		int     passwordlen,// In: password length
		BYTE   *filedata,   // In: pointer to the file data
		int     filesize);  // In: size of the data to write

	//-------------------------------------------------------------------------------
	//	Load and decrypt file stored on the host drive (password-based encryption)
	//-------------------------------------------------------------------------------
	int V2X_LoadFromHostFile(
		char   *filename,   // In: file name
		BYTE   *password,   // In: encryption password
		int     passwordlen,// In: password length
		BYTE   *filedata,   // Out: decrypted file data will be copied here
		int    *datalen);   // Out: actual file size, initially contains max file size

	//-------------------------------------------------------------------------------
	//	Get referenced key ID from the V2X Prototype, load and decrypt the key from respective
	//  file stored on the host drive
	//-------------------------------------------------------------------------------
	int V2X_LoadUserKey(
		BYTE *keyID,            // In: pointer to KeyID (4 bytes)
		char *util_password,    // In: password used to decrypt the key file
		BYTE *userkey,          // Out: key will be copied here
		int  *userkeysize);     // Out: key size will be copied here

#endif


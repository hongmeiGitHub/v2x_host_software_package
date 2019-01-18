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

#include "crypto_wrapper.h"


/*******************************
*    Variable Definitions      *
*******************************/

// Algorithms defined by IEEE1609.2
//------------------------------------------

static EC_KEY *PubKey = NULL; // Current public key.
static EC_KEY *PrivKey = NULL; // Current private key.
static EC_KEY *EphemeralKey = NULL; // Current EphemeralKey key.
static EC_GROUP *EccGroup = NULL;
static char *ECC_Curve_Name[MAX_CURVES] = {
	"prime256v1",
	"brainpoolP256r1",
	"secp384r1",
	"brainpoolP384r1",
};

static EVP_CIPHER_CTX *ctx;

static const EVP_CIPHER *cipher;
static BYTE  bIV[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };



/*******************************
*    Function Definitions      *
*******************************/

//--------------------------------------------------------------------
// ISO padding implementation for AES (16 bytes block)
//--------------------------------------------------------------------
int ISO_padding_16 (BYTE *data, int len)
{
    data[len++] = 0x80;
    while (len % 16) data[len++] = 0;
    return len;
}

//--------------------------------------------------------------------
// ISO padding implementation
//--------------------------------------------------------------------
int Remove_ISO_padding (BYTE *data, int len)
{
    if (len == 0) return 0;
    do {
        len--;
        if (data[len] == 0x80) { return len; }
    } while (len != 0 && data[len] == 0);
    return len;
}

//--------------------------------------------------------------------
// SetAlgCrypto                             OpenSSL version.
//--------------------------------------------------------------------
static int SetAlgCrypto (ALG_ID algID,
                         int encMode)
{
//-------------------------------------- AES: 16 bytes key ------------------------------------------
    if      (algID == ALG_AES_128  && encMode == CRYPT_MODE_ECB) cipher = EVP_aes_128_ecb();
    else if (algID == ALG_AES_128  && encMode == CRYPT_MODE_CBC) cipher = EVP_aes_128_cbc();
//-------------------------------------- AES: 24 bytes key ------------------------------------------
    else if (algID == ALG_AES_192  && encMode == CRYPT_MODE_ECB) cipher = EVP_aes_192_ecb();
    else if (algID == ALG_AES_192  && encMode == CRYPT_MODE_CBC) cipher = EVP_aes_192_cbc();
//-------------------------------------- AES: 32 bytes key ------------------------------------------
    else if (algID == ALG_AES_256  && encMode == CRYPT_MODE_ECB) cipher = EVP_aes_256_ecb();
    else if (algID == ALG_AES_256  && encMode == CRYPT_MODE_CBC) cipher = EVP_aes_256_cbc();
    else {
        LogError("Invalid algorithm ID (%08X) or Enc. Mode (%08X)!\n", algID, encMode);
        return 0;
    }
    return 1;
}

//--------------------------------------------------------------------
// Encrypt data using AES.                             OpenSSL version
//--------------------------------------------------------------------
int Crypto_Encrypt(BYTE* pbKeyData,
                      int    keyLen,
                      ALG_ID algID,
                      int    encMode,
                      BYTE*  pbInBuffer,
                      int    inputDataLen,
                      BYTE*  pbOutBuffer,
                      int   *pOutputDataLen)
{
    int outLen, blSize, ret = -1;

    ctx = EVP_CIPHER_CTX_new();

    if (!SetAlgCrypto(algID, encMode)) goto enc_exit;

    if (!EVP_EncryptInit_ex (ctx, cipher, 0, pbKeyData, bIV)) goto enc_exit;

    if (!EVP_CIPHER_CTX_set_padding(ctx,0)) goto enc_exit;

    if (!EVP_EncryptUpdate(ctx, pbOutBuffer, &outLen, pbInBuffer, inputDataLen)) goto enc_exit;

    if (!EVP_EncryptFinal_ex(ctx, pbOutBuffer + outLen, &blSize)) goto enc_exit;

    if (pOutputDataLen) *pOutputDataLen = outLen + blSize;
    ret = 0;
enc_exit:

    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

//--------------------------------------------------------------------
// Decrypt data using AES.                             OpenSSL version
//--------------------------------------------------------------------
int Crypto_Decrypt(BYTE* pbKeyData,
                      int    keyLen,
                      ALG_ID algID,
                      int    encMode,
                      BYTE*  pbInBuffer,
                      int    inputDataLen,
                      BYTE*  pbOutBuffer,
                      int   *pOutputDataLen)
{
    int outLen = 0, blSize, ret = -1;

    ctx = EVP_CIPHER_CTX_new();

   if (!SetAlgCrypto(algID, encMode)) goto dec_exit;

   if (!EVP_DecryptInit_ex (ctx, cipher, 0, pbKeyData, bIV)) goto dec_exit;

   if (!EVP_CIPHER_CTX_set_padding(ctx,0)) goto dec_exit;

   if (!EVP_DecryptUpdate(ctx, pbOutBuffer, &outLen, pbInBuffer, inputDataLen)) goto dec_exit;

   if (!EVP_DecryptFinal_ex(ctx, pbOutBuffer + outLen, &blSize)) goto dec_exit;

   if (pOutputDataLen) *pOutputDataLen = outLen + blSize;
    ret = 0;
dec_exit:

    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

//--------------------------------------------------------------------
// AES_CBC MAC calculation                             OpenSSL version
// or
// HMAC(SHA256)                        Used by ECIES.  OpenSSL version
// MAC1 is HMAC [in IEEE 1363a, Section 14.4.1]
// HMAC with SHA-256 with tag output bitlength tbits = 128
//--------------------------------------------------------------------
int Crypto_MAC(BYTE*  keyvalue,		// MAC key value
                   int    keyLen,	// MAC key length
                   ALG_ID algID,
                   int    encMode,
                   BYTE*  inbuf,	// pointer to a data buffer
                   int    inbuflen,	// data length
                   BYTE*  outbuf)	// pointer to a reserved space for MAC
{
    int j, k;
	int ret = 0;

	if (algID == SESSION_ENC_ALG)
	{
		AES_KEY aeskey;
		AES_set_encrypt_key(keyvalue, keyLen * 8, &aeskey);

		memset(outbuf, 0, MAC_SIZE);
		for (j = 0; j < inbuflen; j += MAC_SIZE)
		{
			for (k = 0; k < MAC_SIZE; k++) { // XOR data with IV or previous block encryption result
				if (j + k < inbuflen) outbuf[k] ^= inbuf[j + k];
				else if (j + k == inbuflen) outbuf[k] ^= 0x80; // Input data ISO padding: 80 00 00 ...
			}
			AES_encrypt(outbuf, outbuf, &aeskey);
		}
		ret = MAC_SIZE;
	}
	else if (algID == ALG_HMAC)
	{
		unsigned int maclen;
		BYTE mac[64];
		const EVP_MD *md_type = ECIES_HASH;

		HMAC_CTX *hmac = NULL;
		hmac = HMAC_CTX_new();
		HMAC_CTX_reset(hmac);
		HMAC_Init_ex(hmac, keyvalue, keyLen, md_type, NULL);
		HMAC_Update(hmac, inbuf, inbuflen);
		HMAC_Final(hmac, mac, &maclen);
		HMAC_CTX_reset(hmac);
		HMAC_CTX_free(hmac);

		if (maclen >= DIGEST_SIZE) {
			maclen = DIGEST_SIZE;
			memcpy(outbuf, mac, maclen);
#ifdef DEBUGALL
			HexDump("HMAC: ", mac, maclen);
#endif
		}
		ret = (int)maclen;
	}

    return ret;
}

//--------------------------------------------------------------------
// Crypto_init
//
// Initializes Elliptic Curve library
//
// Input Parameters:
//	  curve     Elliptic curve type. Example: prime256v1, secp224r1, ...
//
// Output Parameters:
//	  none
//
// Return:
//	  The return value is the error code value.
//	  TRUE - success, FALSE - error
//--------------------------------------------------------------------
int Crypto_init(BYTE algid)
{
	if (algid >= MAX_CURVES) return FALSE;
    if (EccGroup) Crypto_close(); // Already initialized - call Shutdown first

    strncpy(CurveName, ECC_Curve_Name[algid], sizeof(CurveName)-1);
	EccNid = OBJ_sn2nid(ECC_Curve_Name[algid]);
	EccGroup = EC_GROUP_new_by_curve_name(EccNid);
    return TRUE;
}

//--------------------------------------------------------------------
// Crypto_close
//
// Close Elliptic Curve library
//
// Input Parameters:
//	  none
//
// Output Parameters:
//	  none
//
// Return:
//	  none
//--------------------------------------------------------------------
void Crypto_close()
{
    if (PubKey)  EC_KEY_free(PubKey);               PubKey = NULL;
    if (PrivKey) EC_KEY_free(PrivKey);              PrivKey = NULL;
    if (EphemeralKey) EC_KEY_free(EphemeralKey);    EphemeralKey = NULL;
	if (EccGroup) EC_GROUP_free(EccGroup);          EccGroup = NULL;
    CurveName[0] = 0;
}


//--------------------------------------------------------------------
// Crypto_KeyGen
//
// Generate Ephemeral Key Pair
//
// Input Parameters:
//	  ToDo
//
// Output Parameters:
//	  none
//
// Return:
//	  The return value is the error code value.
//	  TRUE - success, FALSE - error
//--------------------------------------------------------------------
int Crypto_KeyGen(BYTE *bPubKey,
                               int  *iPubKeyLen,
                               BYTE *bPrvKey,
                               int  *iPrvKeyLen)
{
    if (EphemeralKey) EC_KEY_free(EphemeralKey);

	EphemeralKey = EC_KEY_new_by_curve_name(EccNid);
    if (EphemeralKey == NULL) { LogError("ERROR: Crypto_ECC_GenerateEphemeralKeyPair: EC_KEY_new_by_curve_name: %s\n", ERR_error_string(ERR_get_error(), NULL));
                                return FALSE; }
	if (EC_KEY_generate_key(EphemeralKey) != 1) {
		LogError("ERROR: Crypto_ECC_GenerateEphemeralKeyPair: EC_KEY_generate_key failed. %s\n",
                       ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(EphemeralKey);
        EphemeralKey = NULL;
		return FALSE;
	}
    *iPubKeyLen = EC_POINT_point2oct(EC_KEY_get0_group(EphemeralKey),
                                      EC_KEY_get0_public_key(EphemeralKey),
                                      POINT_CONVERSION_COMPRESSED,
                                      bPubKey,
                                      *iPubKeyLen,
                                      NULL);
    if (*iPubKeyLen == 0) {
        LogError("ERROR: EC_POINT_point2oct: Public key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
    *iPrvKeyLen = BN_bn2bin(EC_KEY_get0_private_key(EphemeralKey), bPrvKey);
    if (*iPrvKeyLen == 0) {
        LogError("ERROR: EC_POINT_point2oct: Private key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
	return TRUE;
}

//--------------------------------------------------------------------
// Crypto_ECC_SetPublicKey
//
// Sets the value of internal Public key (EC_KEY)
//
// Input Parameters:
//	  pubkey:    binary representation of a public key
//	  keylen:    public key length
//
// Output Parameters:
//	  none
//
// Return:
//	  The return value is the error code value.
//	  TRUE - success, FALSE - error
//--------------------------------------------------------------------
int Crypto_ECC_SetPublicKey(BYTE *pubKey, int keylen)
{
    int ret = FALSE;

    BIGNUM *BigNum = BN_new();
	BN_bin2bn(pubKey, keylen, BigNum);

    if (PubKey) EC_KEY_free(PubKey);
	PubKey = EC_KEY_new_by_curve_name(EccNid);
    if (PubKey == NULL) { LogError("EC_KEY_new_by_curve_name: %s\n", ERR_error_string(ERR_get_error(), NULL));
                          goto SetPubKey_exit; }
	EC_KEY_set_public_key(PubKey, EC_POINT_bn2point(EccGroup, BigNum, NULL, NULL));

    if (!EC_KEY_check_key(PubKey)) {
        LogError("EC_KEY_check_key: Invalid Public Key. Curve: %s\n", CurveName);
        LogError("%s\n", ERR_error_string(ERR_get_error(), NULL));
        goto SetPubKey_exit;
    }
    ret = TRUE;
SetPubKey_exit:
    if (BigNum)  BN_free(BigNum);
    return ret;
}

//--------------------------------------------------------------------
// Crypto_ECC_SetPrivateKey
//
// Sets the value of internal Private key (EC_KEY)
//
// Input Parameters:
//	  PrivKey:  binary representation of private key
//	  keylen:   private key length
//
// Output Parameters:
//	  none
//
// Return:
//	  The return value is the error code value.
//	  TRUE - success, FALSE - error
//--------------------------------------------------------------------
int Crypto_ECC_SetPrivateKey(BYTE *privkey, int keylen)
{
    BIGNUM *BigNum = BN_new();
	BN_bin2bn(privkey, keylen, BigNum);

    if (PrivKey) EC_KEY_free(PrivKey);
    PrivKey = EC_KEY_new_by_curve_name(EccNid);
    if (PrivKey == NULL) { LogError("ERROR: Invalid Private Key. Curve: %s\n", CurveName); goto SetPrivateKey_exit; }

	EC_KEY_set_private_key(PrivKey, BigNum);

SetPrivateKey_exit:
    if (BigNum)  BN_free(BigNum);
    return TRUE;
}

//--------------------------------------------------------------------
// SHA digest calculation
// Returns: 1 - success, 0 = error
//--------------------------------------------------------------------
int Crypto_Hash(BYTE *msg,
             int   mlen,
             BYTE *hash,
             int   hashlen)
{
    if      (hashlen == SHA_DIGEST_LENGTH)     return SHA1  (msg, mlen, hash) ? 1 : 0;
    else if (hashlen == SHA224_DIGEST_LENGTH)  return SHA224(msg, mlen, hash) ? 1 : 0;
    else if (hashlen == SHA256_DIGEST_LENGTH)  return SHA256(msg, mlen, hash) ? 1 : 0;
    else if (hashlen == SHA384_DIGEST_LENGTH)  return SHA384(msg, mlen, hash) ? 1 : 0;
    else if (hashlen == SHA512_DIGEST_LENGTH)  return SHA512(msg, mlen, hash) ? 1 : 0;
    return 0;
}

//--------------------------------------------------------------------
// Generate ECDSA-SHA256 signature
// Returns: length of the signature generated, 0 = error
//--------------------------------------------------------------------
int Crypto_ECDSA_Sign(BYTE *privKeyBytes,
                         int     privlen,
                         BYTE   *digest,
                         int     digestlen,
                         BYTE   *signature)
{
    int ret = 0;
    BYTE *psign = signature;
    BIGNUM *BigNum = BN_new();
    EC_KEY *privkey = NULL;
    ECDSA_SIG *sig;

	BN_bin2bn(privKeyBytes, privlen, BigNum);

    privkey = EC_KEY_new_by_curve_name(EccNid);
    if (privkey == NULL) { LogError("ERROR: Invalid Private Key. Curve: %s\n", CurveName); goto Sign_ECDSA_exit; }

	EC_KEY_set_private_key(privkey, BigNum);

	sig = ECDSA_do_sign((const BYTE *)digest, digestlen, privkey);
	ret = i2d_ECDSA_SIG(sig, &psign);

Sign_ECDSA_exit:
    if (privkey) EC_KEY_free(privkey);
    if (BigNum)  BN_free(BigNum);
    return ret;
}

//--------------------------------------------------------------------
// Verify ECDSA-SHA1 signature
// Returns: 1 - signature verified OK,   other - error
//--------------------------------------------------------------------
int Crypto_ECDSA_Verify(BYTE *pubKeyBytes,
                         int      publen,
                         BYTE    *digest,
                         int      digestlen,
                         BYTE    *signature,
                         int      signlen)
{
    int ret = 0;
	BYTE *psign = signature;
    ECDSA_SIG *sig;
    EC_KEY *pubkey;

    BIGNUM *BigNum = BN_new();
	BN_bin2bn(pubKeyBytes, publen, BigNum);

	pubkey = EC_KEY_new_by_curve_name(EccNid);
    if (pubkey == NULL) { LogError("ERROR: EC_KEY_new_by_curve_name: %s\n", ERR_error_string(ERR_get_error(), NULL));
                          goto Verify_ECDSA_exit; }
	EC_KEY_set_public_key(pubkey, EC_POINT_bn2point(EccGroup, BigNum, NULL, NULL));

    if (!EC_KEY_check_key(pubkey)) {
        LogError("EC_KEY_check_key: Invalid Public Key. Curve: %s\n", CurveName);
        LogError("%s\n", ERR_error_string(ERR_get_error(), NULL));
        goto Verify_ECDSA_exit;
    } 
	sig = d2i_ECDSA_SIG(NULL, (const BYTE **)&psign, signlen);
    if (sig == NULL) { LogError("d2i_ECDSA_SIG: Invalid Signature format\n"); goto Verify_ECDSA_exit; }

	ret = ECDSA_do_verify((const BYTE *)digest, digestlen, (const ECDSA_SIG *)sig, pubkey);

Verify_ECDSA_exit:
    if (BigNum)  BN_free(BigNum);
    if (pubkey) EC_KEY_free(pubkey);
    return ret;
}
//--------------------------------------------------------------------
// Generate ECDH shared secret                     OpenSSL version.
// Note that [FIPS186-3] refers to secp224r1 as P-224,
// secp256r1 as P-256, secp384r1 as P-384, and secp521r1 as P-521
//--------------------------------------------------------------------
int Crypto_ECDH( BYTE  hashalg,
                 BYTE *pubkey,		// Remote party ECC public key in DER format
                 int   pubkeylen,	// Remote party ECC public key length
                 BYTE *privkey,		// Local party private key
                 int   privkeylen,	// Local party private key length
                 BYTE *sharedsecret)	// pointer to a buffer for decrypted signature
{
    EC_KEY      *ecpubkey = NULL;
    EC_KEY      *ecprivkey = NULL;
    EC_POINT    *ecpubpoint = NULL;
    BIGNUM      *bnprivateKey = NULL;
    BYTE        secret[128];
    int         field_size, secret_len;
    int outlen;

	ecpubkey = EC_KEY_new_by_curve_name(EccNid);
    ecpubpoint = EC_POINT_new(EccGroup);

    EC_POINT_oct2point(EccGroup, ecpubpoint, pubkey, pubkeylen, NULL);
    EC_KEY_set_public_key(ecpubkey, ecpubpoint);

    if (!EC_KEY_check_key(ecpubkey)) {
        LogError("EC_KEY_check_key failed:\n");
        LogError("%s\n",ERR_error_string(ERR_get_error(),NULL));
        return 0;
    }
    else {
#ifdef DEBUGALL
        LogAll("Public key verified OK\n");
#endif
    }

    bnprivateKey = BN_new();
    BN_bin2bn(privkey, privkeylen, bnprivateKey);
    ecprivkey = EC_KEY_new_by_curve_name(EccNid);
    EC_KEY_set_private_key(ecprivkey, bnprivateKey);
    BN_free(bnprivateKey);

    // Calculate the size of the buffer for the shared secret:
    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(ecpubkey));
    secret_len = (field_size+7)/8;

    ECDH_compute_key(secret, secret_len, ecpubpoint, ecprivkey, NULL); // KDF1_SHA);

    if (hashalg == 0) {
        outlen = secret_len;
        memmove(sharedsecret, secret, secret_len); // Plain: Shared secret without hash
    }
    else {
        outlen = hashalg; // = digest size in bytes
        Crypto_Hash(secret, secret_len, sharedsecret, hashalg);  // SHA after ECDH
    }
#ifdef DEBUGALL
    if (outlen) HexDump("ECDH: ", secret, outlen);
#endif
    return outlen;
}

//--------------------------------------------------------------------
// KDF2 with SHA-256                   Used by ECIES. OpenSSL version.
// X9.63 or IEEE1363a [Section 13.2].
// KDF(SS, KDP) = SHA256(SS || counter || KDP)
// concatinating output blocks for counter in [1, ceil(outLen/block_len)]
//--------------------------------------------------------------------
int Crypto_KDF (BYTE *sharedsecret,	// In: pointer to shared secret
                       int   ssLen,	// In: shared secret length
                       BYTE *kdp,	// In: Optional: pointer to key derivation parameter
                       int  kdpLen,	// In: Optional: key derivation parameter length
                       int  outLen,	// In: desired output length
                       BYTE *kdf_out)	// Out: Returns the derived key
{
    BYTE hash_input[512];
    int cnt;

    memset(hash_input, 0, sizeof(hash_input));
    memcpy(hash_input, sharedsecret, ssLen);    // SS - 16 bytes
    if (kdp && kdpLen)
        memcpy(hash_input+ssLen+4, kdp, kdpLen);// Optional key derivation parameter (32 bytes)

    for (cnt = 0; cnt <= outLen/DIGEST_SIZE; cnt++) {
        hash_input[ssLen+3] = cnt+1;            // counter - 4 bytes
        SHA256(hash_input, ssLen+4+kdpLen, kdf_out + SHA256_DIGEST_LENGTH * cnt);
    }
#ifdef DEBUGALL
    if (outLen) HexDump("KDF2: ", kdf_out, outLen);
#endif
	return 1;
}

//--------------------------------------------------------------------
// ECIES encryption                                 OpenSSL version
// Returns length of encrypted data or zero in case of error
//--------------------------------------------------------------------
int Crypto_ECIES_Encrypt(BYTE *bRecPubKey,	// In: pointer to recipient public key
                         int   iRecPubLen,      // In: recipientpublic key length
                         BYTE *bEphPrvKey,      // In: pointer to ephemeral private key
                         int  iEphPrvLen,       // In: ephemeral private key length.
                         BYTE *kdpdata,         // In: Optional: hash of recipient info (key derivation parameters)
                         int   kdplength,       // In: Optional: recipient info length
                         BYTE *plaindata,       // In: data to encrypt
                         int   plainlength,     // In: data length
                         BYTE *encrdata,        // Out: pointer to array for output data
                         BYTE *authtag,         // Out: pointer to array for authentication tag
                         int  *authlength)      // Out: pointer to authentication tag length
{
    BYTE KDF2[256];
    BYTE sharedsecret[DIGEST_SIZE],
         K1[AES128_KEY_SIZE],
         K2[256];

    if (!bRecPubKey || !iRecPubLen || !plaindata || !plainlength || !encrdata) {
        LogError("ERROR: Crypto_ECIES_Encrypt: Invalid parameters\n");
        return 0;
    }
    // Convert recepient's public key from binary form into EC_KEY structure
    if (!Crypto_ECC_SetPublicKey(bRecPubKey, iRecPubLen)) {
        LogError("ERROR: Crypto_ECIES_Encrypt: Invalid recipient public key\n");
        return 0;
    }
    // Use ECDH with recipient public and ephemeral private keys to generate the shared secret
    if (Crypto_ECDH(0,  bRecPubKey, iRecPubLen,
                        bEphPrvKey, iEphPrvLen,
                        sharedsecret) != DIGEST_SIZE) {
        LogError("ERROR: Crypto_ECIES_Encrypt: Crypto_ECDH: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
    // Use KDF2 to generate the ENC key (16 bytes) and MAC key (32 bytes)
    Crypto_KDF(sharedsecret, ECDH_SIZE, kdpdata, kdplength, AES128_KEY_SIZE + DIGEST_SIZE, KDF2);
    memcpy(K1, KDF2, AES128_KEY_SIZE);
    memcpy(K2, KDF2+AES128_KEY_SIZE, DIGEST_SIZE);

    // Encrypt using AES CCM ??? or XOR ???
    memcpy(encrdata, plaindata, AES128_KEY_SIZE);
    Xor(K1, encrdata, AES128_KEY_SIZE);
    *authlength = Crypto_MAC(K2, DIGEST_SIZE, ALG_HMAC, 0, encrdata, AES128_KEY_SIZE, authtag);
    if (*authlength != DIGEST_SIZE) return 0;
    *authlength = ECIES_TAG_SIZE; // IEEE1609.2 limits to 16 bytes
    return AES128_KEY_SIZE;
}

//--------------------------------------------------------------------
// ECIES decryption and tag verification               OpenSSL version
// Returns length of decrypted data or zero in case of error
//--------------------------------------------------------------------
int Crypto_ECIES_Decrypt(BYTE *bRecPrvKey,      // In: pointer to recipient private key
                         int   iRecPrvLen,      // In: private key length
                         BYTE *bEphPubKey,      // In: pointer to ephemeral public key
                         int  iEphPubLen,       // In: ephemeral public key length
                         BYTE *kdpdata,         // In: Optional: hash of recipient info (key derivation parameters)
                         int   kdplength,       // In: Optional: recipient info length
                         BYTE *encrdata,        // In: pointer to data to decrypt
                         int   encrlength,      // In: encrypted data length
                         BYTE *authtag,         // In: Optional: pointer to authentication tag
                         int   authlength,      // In: Optional: authentication tag length
                         BYTE *plaindata)       // Out: pointer to plain text length
{
    BYTE KDF2[256];
    BYTE sharedsecret[DIGEST_SIZE],
         atag[64],
         K1[AES128_KEY_SIZE],
         K2[256];
    int atagLen;

    if (!bRecPrvKey || !iRecPrvLen || !encrdata || !encrlength || !plaindata) {
        LogError("ERROR: Crypto_ECIES_Decrypt: Invalid parameters\n");
        return 0;
    }
    if (authlength != 0 && authlength !=  ECIES_TAG_SIZE)
        { LogError("ERROR: Crypto_ECIES_Decrypt: Wrong Auth.tag length: %d bytes\n", authlength); return 0; }

    // Convert recepient's public key from binary form into EC_KEY structure
    if (!Crypto_ECC_SetPrivateKey(bRecPrvKey, iRecPrvLen)) {
        LogError("ERROR: Crypto_ECIES_Decrypt: Invalid recipient private key\n");
        return 0;
    }
    // Use ECDH with recipient public and ephemeral private keys to generate the shared secret
    if (Crypto_ECDH(0,  bEphPubKey, iEphPubLen,
                        bRecPrvKey, iRecPrvLen,
                        sharedsecret) != DIGEST_SIZE) {
        LogError("ERROR: Crypto_ECIES_Decrypt: Crypto_ECDH: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
    // Use KDF2 to generate the ENC key (16 bytes) and MAC key (32 bytes)
    Crypto_KDF(sharedsecret, ECDH_SIZE, kdpdata, kdplength, AES128_KEY_SIZE + DIGEST_SIZE, KDF2);
    memcpy(K1, KDF2, AES128_KEY_SIZE);
    memcpy(K2, KDF2+AES128_KEY_SIZE, DIGEST_SIZE);

    // Decrypt using AES CCM ??? or XOR ???
    memcpy(plaindata, encrdata, AES128_KEY_SIZE);
    Xor(K1, plaindata, AES128_KEY_SIZE);

    // Calculate tags over the encrypted data
    if ((atagLen = Crypto_MAC(K2, DIGEST_SIZE, ALG_HMAC, 0, encrdata, encrlength, atag)) != DIGEST_SIZE)
        { LogError("ERROR: Crypto_ECIES_Decrypt: Crypto_MAC: %s\n", ERR_error_string(ERR_get_error(), NULL)); return 0; }

    atagLen = ECIES_TAG_SIZE; // IEEE1609.2 limits to 16 bytes

    // Compare tags
    if (memcmp(atag, authtag, ECIES_TAG_SIZE) != 0) {
        LogError("ERROR: Crypto_ECIES_Decrypt: Received authentication tag:\n");
        HexDump("            ", authtag, authlength);
        HexDump("Calculated: ", atag, atagLen);
        return 0;
    }
    return AES128_KEY_SIZE;
}

//------------------------------------------------------------------------
// Hash to Integer mod n (Part of ECQV Key Reconstruction)
//    e = Hn(CertU) mod n
//    - CertU: {octet string} tbsCert || PU (see note above)
//
// Input:  CertU
// Output: Integer e
//------------------------------------------------------------------------
int Crypto_ECQV_HashToInteger(uint8_t   *certU, // In: The digest of CertU mod n
                       size_t  certLen,		// In: The length of Certu
                       uint8_t   *e)		// Out: e
{
    BIGNUM *bn_hash, *bn_e;
    int eLen;
    BYTE hash[64];

    if (!SHA256(certU, certLen, hash)) { LogError("Error: SHA256\n"); return 0; }
#ifdef DEBUGALL
    HexDump("CertU: ", certU, certLen);
    HexDump("SHA:   ", hash, SHA256_DIGEST_LENGTH);
#endif
    bn_hash = BN_new();

    bn_e = BN_new();

    // e = leftmost floor(log_2 n) bits of SHA-256(CertU), i.e.
    // e = Shiftright(SHA-256(CertU)) by 1 bit
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, bn_hash); // Hash -> bignum
    BN_rshift1(bn_e, bn_hash);    // Shift right by 1

    eLen = BN_bn2bin(bn_e, e);
#ifdef DEBUGALL
    HexDump("e:     ", e, eLen);
#endif

    BN_free(bn_hash);
    BN_free(bn_e);

    return eLen;
}

//------------------------------------------------------------------------
// Reconstruct Private key - SEC4 Cert_Reception
//    e = Hn(CertU)
//    dU = e * (kU + f) + r   mod n
//
// Private Key Reconstruction Inputs:
//    - kU:    {octet string} User's certificate request private key, corresponding to RU
//    - CertU: {octet string} tbsCert || PU (see note above)
//    - r:     {octet string} private key reconstruction value
//
// Private Key Reconstruction Output:
//    - dU:    {octet string} User's (reconstructed) private key
//------------------------------------------------------------------------
int Crypto_ECQV_Reception(
                 ECPrivateKey *prvkey,		// In: private key
                 uint8_t         *e,		// In: Optional: The digest of CertU mod n. NULL if not used, default 1
                 size_t        eLen,		// In: Optional: The length of the e buffer. Zero if not used.
                 uint8_t         *r,		// In: Optional: reconstruction value r. NULL if not used, default 0
                 size_t        rLen,		// In: Optional: The length of the r. Zero if not used.
                 uint8_t         *f,		// In: Optional: f() for butterfly keys. NULL if not used, default 0
                 size_t        fLen,		// In: Optional: The length of the f buffer. Zero if not used.
                 ECPublicKey *newpubkey,	// Out: Reconstructed public key is copied to this pointer/address
                 ECPrivateKey *newprvkey)	// Out: Reconstructed private key is copied to this pointer/address
{

    EC_GROUP * group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // curve secp256r1 is the same as prime256v1
    const EC_POINT * G = EC_GROUP_get0_generator(group);
    EC_POINT * pub = EC_POINT_new(group);
    BN_CTX * ctx = BN_CTX_new();

    BIGNUM *bn_priv, *bn_e, *bn_kU, *bn_fkU, *bn_ekU, *bn_r, *bn_n, *bn_f;

    bn_priv = BN_new();

    bn_kU = BN_new();

    bn_fkU = BN_new();

    bn_ekU = BN_new();

    bn_e = BN_new();

    bn_r = BN_new();

    bn_n = BN_new();

    bn_f = BN_new();

    EC_GROUP_get_order(group, bn_n, ctx);

#ifdef DEBUGALL
    //EC_POINT_point2oct(group, G, POINT_CONVERSION_UNCOMPRESSED, bArray, sizeof(bArray), ctx);
    //HexDump("G:   ", bArray, 65);
    //iLen = BN_bn2bin(&bn_n, bArray);
    //HexDump("N:   ", bArray, iLen);

    HexDump("kU:  ", prvkey->blob, prvkey->len);
    HexDump("e:   ", e, eLen);
    HexDump("r:   ", r, rLen);
    HexDump("f:   ", f, fLen);
#endif
    // dU = e * (kU + f) + r   mod n
    //-----------------------------------------------
    BN_bin2bn(f, fLen, bn_f);                      // f -> bignum
    BN_bin2bn(prvkey->blob, prvkey->len, bn_kU);   // kU -> bignum bn_kU
    BN_mod_add(bn_fkU, bn_f, bn_kU, bn_n, ctx); // fkU = kU + f

    BN_bin2bn(e, eLen, bn_e);                      // e -> bignum
    BN_mod_mul(bn_ekU, bn_e, bn_fkU, bn_n, ctx);// ekU = e * (kU + f)

    BN_bin2bn(r, rLen, bn_r);                      // r -> bignum bn_r
    BN_mod_add(bn_priv, bn_r, bn_ekU, bn_n, ctx);// private dU = e * (kU + f) + r

    newprvkey->len = BN_bn2bin(bn_priv, newprvkey->blob);

    // Reconstruct Public key: QU = dU * G
    //------------------------------------------------------------------------
    BN_bin2bn(newprvkey->blob, newprvkey->len,bn_priv);

    //EC_POINT_mul calculates the value generator * n + q * m and stores the result in r. The value n may be NULL in which case the result is just q * m.
    //int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
    EC_POINT_mul(group, pub, NULL, (EC_POINT *)EC_GROUP_get0_generator(group), bn_priv, ctx);

    newpubkey->len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED /*POINT_CONVERSION_COMPRESSED*/, newpubkey->blob, ECC_PUB_KEY_SIZE, ctx);

#ifdef DEBUGALL
    HexDump("Reconstructed private key: ", newprvkey->blob, newprvkey->len);
    HexDump("Reconstructed public key:  ", newpubkey->blob, newpubkey->len);
#endif
    BN_CTX_free(ctx);
    EC_POINT_free(pub);
    EC_GROUP_free(group);

    BN_free(bn_priv);
    BN_free(bn_e);
    BN_free(bn_kU);
    BN_free(bn_fkU);
    BN_free(bn_ekU);
    BN_free(bn_r);
    BN_free(bn_n);
    BN_free(bn_f);

    return 1;
}

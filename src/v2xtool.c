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

#include "v2xtool.h"

#include "testvectors_ecies.c" // ECIES variables and test vectors
#include "testvectors_ecqv.c" // ECQV variables and test vectors
#include "testvectors_ecdh.c" // ECDH variables and test vectors
#include "testvectors_sha.c" // SHA variables and test vectors
#include "testvectors_hmac.c" // HMAC variables and test vectors
#include "testvectors_kdf.c" // KDF2 variables and test vectors


/*******************************
*    Variable Definitions      *
*******************************/

int KeyIndex = 1;

PKAlgorithm AlgID = ECDSA_NISTP256_WITH_SHA256;
//PKAlgorithm AlgID = ECDSA_BRAINPOOLP256_WITH_SHA256;
//PKAlgorithm AlgID = ECDSA_NISTP384_WITH_SHA256;
//PKAlgorithm AlgID = ECDSA_BRAINPOOLP384_WITH_SHA256;

ECPublicKey ECEphemeralPublicKey = { ECC_PUB_KEY_SIZE, EphemeralPublicKey }; // Ephemeral public key
ECPrivateKey ECEphemeralPrivateKey = { ECC_PRIV_KEY_SIZE, EphemeralPrivateKey }; // Ephemeral private key
ECPublicKey ECRecipientPublicKey = { ECC_PUB_KEY_SIZE, RecipientPublicKey }; // Recipient public key
ECPrivateKey ECRecipientPrivateKey= { ECC_PRIV_KEY_SIZE, RecipientPrivateKey }; // Recipient private key
ECPublicKey ECPublicKeyChip = { ECC_PUB_KEY_SIZE, PublicKeyChip };
ECPrivateKey ECPrivKeyChip = { ECC_PRIV_KEY_SIZE, BYTE_PrivKeyChip };
ECPublicKey ECPublicKeyVerify = { ECC_PUB_KEY_SIZE, PublicKeyVerify };
ECPrivateKey ECPrivKeyVerify = { ECC_PRIV_KEY_SIZE, BYTE_PrivKeyVerify };
ECPublicKey TestHMAC_key = { DIGEST_SIZE, BYTE_TestHMAC_key }; // Using ECPublicKey for HMAC key


// Host software signing certificate authority (CA)
//-----------------------------------------------------------------------------------
uint32_t SignerPubKeyIndex = 0xE000; // Signer's public key stored in V2X Prototype's File 0
uint32_t SoftwareEncryptionKeyIndex = 0xF007; // AES encr. key stored as User Key 7

// Use case test: Example of Host Software CA public key
BYTE bPubKey_CA_ECC256[] = {
    0x04,
    0xea,0xd2,0x18,0x59,0x01,0x19,0xe8,0x87,0x6b,0x29,0x14,0x6f,0xf8,0x9c,0xa6,0x17,0x70,0xc4,0xed,0xbb,0xf9,0x7d,0x38,0xce,0x38,0x5e,0xd2,0x81,0xd8,0xa6,0xb2,0x30,
    0x28,0xaf,0x61,0x28,0x1f,0xd3,0x5e,0x2f,0xa7,0x00,0x25,0x23,0xac,0xc8,0x5a,0x42,0x9c,0xb0,0x6e,0xe6,0x64,0x83,0x25,0x38,0x9f,0x59,0xed,0xfc,0xe1,0x40,0x51,0x41};
ECPublicKey ECPubK_CA_ECC256 = { 0x41, bPubKey_CA_ECC256 };

// Use case test: Host Software CA private key
BYTE bPrivKey_CA_ECC256[] = {0x7d,0x7d,0xc5,0xf7,0x1e,0xb2,0x9d,0xda,0xf8,0x0d,0x62,0x14,0x63,0x2e,0xea,0xe0,0x3d,0x90,0x58,0xaf,0x1f,0xb6,0xd2,0x2e,0xd8,0x0b,0xad,0xb6,0x2b,0xc1,0xa5,0x34};
ECPrivateKey ECPrvK_CA_ECC256= { 0x20, bPrivKey_CA_ECC256 };
//-----------------------------------------------------------------------------------


int offset = 0;
int Power_on = 1;

int UserID = 0;

BYTE UserKey[MAX_USERS][USER_KEY_SIZE+1] = {  // Test Transport/Admin/Users passwords/keys
    {0x00},                                   // User 0 - Transport key
    {"1234567812345678"},                     // User 1 - Admin.   Ex., allowed to change user passwords
    {"12345678"},                             // User 2 - password/key used to authenticate V2X software stack
    {"12345678123"},                          // User 3 - not used, user defined
    {"123456781234"},                         // User 4 - not used, user defined
    {"1234567812345"},                        // User 5 - not used, user defined
    {"123456781234567"},                      // User 6 - not used, user defined
    {"12345678123456781234567812345678"}      // User 7 - user defined. Ex., AES256 key for host software image encryption
};
int UserKeySize[MAX_USERS] = {  // User passwords/keys sizes
     0,                         // User 0 - Transport key
    16,                         // User 1 - Admin.   Ex., allowed to change user passwords
     8,                         // User 2 - password/key used to authenticate V2X software stack
     3,                         // User 3 - not used, user defined
     4,                         // User 4 - not used, user defined
     5,                         // User 5 - not used, user defined
     6,                         // User 6 - not used, user defined
    32                          // User 7 - user defined. Ex., AES256 key for host software image encryption
};
BYTE UserKeyID[MAX_USERS][KEYIDSIZE]={// User Key/password identifiers
    {0x64,0x81,0xC2,0x2F}, // Default Firmware ver.2.0.5 Transport (User 0} key ID, this version didn't support GETDATA(KeyID)
    {0x33,0xCD,0xBC,0x38}, // Default Firmware ver.2.0.5 Admin (User 1} key ID
    {0xEF,0x79,0x7C,0x81}, // Default Firmware ver.2.0.5 User 2 key ID
};



/*******************************
*    Function Definitions      *
*******************************/


//-------------------------------------------------------------------------------
//	Execute a command represented as a Hex text string (CLA INS P1 P2 Lc Data Le).
//	Send command APDU receive response APDU, check returned SW1 SW2 code.
//-------------------------------------------------------------------------------
int APDU(char *str_apdu)
{
	int APDUsize = UTIL_hexStrToArray(str_apdu, APDUbuffer, sizeof(APDUbuffer));
	if (APDUsize == 0) {
		LogError("ERROR: Invalid command APDU: [%s]\n", str_apdu ? str_apdu : "Null");
		return 0;
	}
    return V2X_send_apdu(UserID, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
}
//-------------------------------------------------------------------------------
// Verify signature on the host using OpenSSL
//-------------------------------------------------------------------------------
int VerifySignature(BYTE *pubkey, int pubsize,
                    BYTE *message, int messagesize,
                    BYTE *signature, int sigsize)
{
    int ret;
    BYTE SignatureBER[512];
    BYTE digest[DIGEST_SIZE+1];

    //--------------- Verify with OpenSSL ---------------------
    // Convert 02 || r || s signature format to BER-TLV
    siglen=0;
    SignatureBER[siglen++] = 0x30;
    SignatureBER[siglen++] = 0x44;
    SignatureBER[siglen++] = 0x02;
    SignatureBER[siglen++] = ECC_PRIV_KEY_SIZE;
    memcpy(SignatureBER+siglen, signature+1, ECC_PRIV_KEY_SIZE);
    siglen += ECC_PRIV_KEY_SIZE;
    SignatureBER[siglen++] = 0x02;
    SignatureBER[siglen++] = ECC_PRIV_KEY_SIZE;
    memcpy(SignatureBER+siglen, signature+1+ECC_PRIV_KEY_SIZE, ECC_PRIV_KEY_SIZE);
    siglen += ECC_PRIV_KEY_SIZE;

   	Crypto_Hash(message, messagesize, digest, DIGEST_SIZE);

    // Verify signature using OpenSSL
    ret = (Crypto_ECDSA_Verify( pubkey, pubsize,
                                digest, DIGEST_SIZE,
                                SignatureBER, siglen) == 0)? 1 : 0;
    return ret;

    //--------------- Verify with V2X Prototype (standard ECDSA) ---------------------
    //LogScreen("ECDSA standard verify:\n");
    //LogScreen("------------------------------------\n");
    //Crypto_Hash(MessageData, MessageSize, DigestData, DIGEST_SIZE); // Calculate SHA256 locally

    //siglen=0;
    //SignatureBER[siglen++] = 0x02;
    //SignatureBER[siglen++] = ECC_PRIV_KEY_SIZE;
    //memcpy(SignatureBER+siglen, Signature+1, ECC_PRIV_KEY_SIZE);
    //siglen += ECC_PRIV_KEY_SIZE;
    //memcpy(SignatureBER+siglen, Signature+1+ECC_PRIV_KEY_SIZE, ECC_PRIV_KEY_SIZE);
    //siglen += ECC_PRIV_KEY_SIZE;

    //if (V2X_ecdsa_verify(AlgID,
    //                         KeyIndex,
    //                         DigestData,
    //                         DIGEST_SIZE,
    //                         SignatureBER,
    //                         SignatureSize))
    //    LogScreen("Signature verified OK\n");
    //else { errorflag=1; LogError("Signature verification failed !\n");}
}
//-------------------------------------------------------------------------------
//void CheckError()
//{
//    if (errorflag) system("aplay failure.wav >/dev/null 2>&1");
//    else system("aplay ok.wav >/dev/null 2>&1");
//}
//-------------------------------------------------------------------------------
int CheckTestVectorBinary(char *testname, BYTE *bResult, int resultSize, BYTE *bTestVector, int testVectorSize)
{
    if (testVectorSize != resultSize) {
        LogError("ERROR: %s incorrect size: %d, should be: %d\n", testname, resultSize, testVectorSize);
        errorflag=1;
        return 0;
    }
    if (memcmp(bTestVector, bResult, resultSize) != 0) {
        LogError("ERROR: %s is incorrect:\n", testname);
        HexDump("           ", bResult, resultSize);
        HexDump("Should be: ", bTestVector, testVectorSize);
        errorflag=1;
        return 0;
    }
    Log("%s verified - OK\n", testname);
    return 1;
}
//-------------------------------------------------------------------------------
// Saves key to a file on the host. File name is XXXXXXXX.key (X...X = KCV)
// Returns KeyID
//-------------------------------------------------------------------------------
int Save_Key(BYTE *key, int keysize, BYTE *keyid)
{
	char filename[MAX_PATH + 1];
	int ret;

	Calc_KCV_SHA((BYTE*)key, keysize, keyid, KEYIDSIZE);
	sprintf(filename, "%s%02X%02X%02X%02X.key", KEYS_DIR, keyid[0], keyid[1], keyid[2], keyid[3]);
	ret = V2X_SaveToHostFile(filename, UtilPassword, strlen(UtilPassword), (BYTE*)key, keysize);

	if (ret) LogScreen("File %s saved - OK\n", filename);
	return ret;
}
//-------------------------------------------------------------------------------
int CheckTestVector(char *testname, BYTE *bResult, int resultSize, char *sTestVector)
{
    BYTE bTestVector[1024];
    int testVectorSize = UTIL_hexStrToArray(sTestVector, bTestVector, sizeof(bTestVector));
    return CheckTestVectorBinary(testname, bResult, resultSize, bTestVector, testVectorSize);
}
//-------------------------------------------------------------------------------
// Connect to V2X Prototype: ask file encryption password, load and authenticate User key
//-------------------------------------------------------------------------------
int GetUserKey(int userid)
{
    char versionstr[256];
    if ((V2X_FirmwareVersion = V2X_firmware_version(0, versionstr)) == 0) { errorflag = 1; return 0; }
    if (V2X_FirmwareVersion < 200) return 1; // Secure session not supported in firmware < 2.0.x

    if (V2X_FirmwareVersion >= 207) { // Key ID not supported in firmware < 2.0.7 - use default 2.0.5 key
        // Retrieve current User key ID from V2X Prototype
        if (!V2X_GetKeyID(0, userid, UserKeyID[userid])) { errorflag = 1; return 0; }
    }

    // Enter password on the keyboard if it wasn't entered before
    if (!Ask_Password(PASSWORD_PROMPT, UtilPassword)) { errorflag = 1; return 0; }

    // Load User key from file on the host encrypted with utility password
    if (!V2X_LoadUserKey(UserKeyID[userid], UtilPassword, UserKey[userid], &UserKeySize[userid])) { errorflag = 1; return 0; } 
    return 1;
}
//-------------------------------------------------------------------------------
// Use case: Over the air (OTA) Software/Firmware update: Image signing
//-------------------------------------------------------------------------------
int UseCase_OTA_Sign_Software(BYTE *plainData,  int plainDataSize,
                              BYTE *encrData,   int *encrDataSize,
                              BYTE *signature,  int *signatureSize)
{
    BYTE digestData[DIGEST_SIZE];
    //BYTE SignatureBER[512];
    //int ofs1, ofs2;

    LogScreen("OTA: Image signing\n");
    LogScreen("----------------------------------------------------------\n");

    UserID = 1; // Authenticate Admin
    if (!GetUserKey(UserID))  { errorflag = 1; return 0; }
    if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) { errorflag = 1; return 0; }

    // Generate Software image hash
    Crypto_Hash(plainData, plainDataSize, digestData, DIGEST_SIZE); // Calculate SHA256

    // Sign Software image hash (should be generated by the CA)
    //SignatureSize = Crypto_ECDSA_Sign(ECPrvK_TestVectorECC256_Chip.blob, ECPrvK_TestVectorECC256_Chip.len,
    //                                      DigestData, DIGEST_SIZE, SignatureBER);

    //// Convert signature format from BER-TLV to 02 || r || s
    //Signature[0] = 0x02;
    //ofs1 = 4 + SignatureBER[3] - ECC_COORD_SIZE;
    //memcpy(Signature+1, SignatureBER+ofs1, ECC_COORD_SIZE);
    //ofs2 = 2 + SignatureBER[ofs1+ECC_COORD_SIZE+1] - ECC_COORD_SIZE;
    //memcpy(Signature+1+ECC_COORD_SIZE, SignatureBER+ofs1+ECC_COORD_SIZE+ofs2, ECC_COORD_SIZE);
    //SignatureSize = SIGNATURE_SIZE;

    // Use current key slot (KeyIndex) to sign the Software image
    if (!V2X_import_private_key(UserID, AlgID, KeyIndex, &ECPrvK_CA_ECC256))
        { errorflag = 1; return 0; }

    if (!V2X_ecdsa_sign(UserID, AlgID,
                         KeyIndex,
                         digestData,
                         DIGEST_SIZE,
                         signature,
                         signatureSize)) { errorflag=1; LogError("Signature failed !\n");}

    // Encrypt Software (should be done by software/firmware vendor)
    if (!V2X_AES_encrypt(UserID, SoftwareEncryptionKeyIndex, plainData, plainDataSize, encrData, encrDataSize))
        { errorflag=1; LogError("Encryption failed !\n"); return 0; }

    V2X_Close(UserID); // Close Admin session with V2X Prototype
    if (!errorflag) LogScreen("OTA: Data encrypted and signed - OK\n");
    return 1;
}
//-------------------------------------------------------------------------------
// Use case: Over the air (OTA) Software/Firmware update: Image verification
//-------------------------------------------------------------------------------
int UseCase_OTA_Verify_Software(BYTE *encrData,  int encrDataSize,
                                BYTE *signature, int signatureSize,
                                BYTE *plainData, int *plainDataSize)
{
    BYTE digestData[DIGEST_SIZE];

    LogScreen("\nOTA: Image verification\n");
    LogScreen("----------------------------------------------------------\n");

    UserID = 1; // Authenticate Admin
    if (!GetUserKey(UserID))  { errorflag = 1; return 0; }
    if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) { errorflag = 1; return 0; }

    // Use case test: Write Host Software Signing CA public key to File 0
    if (!V2X_import_public_key(UserID, AlgID, SignerPubKeyIndex, &ECPubK_CA_ECC256))
        { errorflag = 1; { errorflag = 1; return 0; } }

    // Decrypt Software update block by block (each block size up to 1800 bytes)
    if (!V2X_AES_decrypt(UserID, SoftwareEncryptionKeyIndex, encrData, encrDataSize, plainData, plainDataSize))
        { errorflag=1; LogError("Decryption failed !\n");}

    // Calculate SHA256 on the host
    Crypto_Hash(plainData, *plainDataSize, digestData, DIGEST_SIZE);

    // V2X Prototype verifies signature of the Software image
    if (V2X_ecdsa_verify(UserID, AlgID,
                         SignerPubKeyIndex,
                         digestData,
                         DIGEST_SIZE,
                         signature,
                         signatureSize))
        LogScreen("Signature verified OK\n");
    else {
		errorflag=1;
		LogError("Signature verification failed !\n");
	}

    V2X_Close(UserID); // Close Admin session with HSM
    if (!errorflag) LogScreen("OTA: Data decrypted and signature verified - OK\n");
    return 1;
}
//-------------------------------------------------------------------------------
int Test_ECQV_Reception(PKAlgorithm algid)
{
    LogScreen("ECQV Reception:\n");
    LogScreen("------------------------------------\n");

    ECPrivKeySeed = ECPrvK_TestVectorECQV;
    if (!V2X_import_private_key(UserID, algid, KeyIndex, &ECPrivKeySeed)) { errorflag = 1; return 0; }

    eSize = Crypto_ECQV_HashToInteger(CertU, sizeof(CertU), ECQV_e);

    if (!V2X_ecqv_reception(UserID, algid,
                       KeyIndex,
                       KeyIndex+1,
                       ECQV_e, eSize,
                       ECQV_r, sizeof(ECQV_r),
                       NULL, 0,
                       &ECPublicKeyChip)) { errorflag = 1; return 0; }

    HexDumpPort("Reconstructed public key:  ", ECPublicKeyChip.blob, ECPublicKeyChip.len);

    if (!V2X_export_private_key(UserID, KeyIndex+1, &ECPrivKeyChip)) {
        Log("Private key reconstruction verification is supported only in Test version of V2X Prototype\n");
        return 1;
    }
    HexDumpPort("Reconstructed private key: ", ECPrivKeyChip.blob, ECPrivKeyChip.len);

    LogScreen("\nReconstructing public/private keys locally for verification:\n");
    if (!Crypto_ECQV_Reception(&ECPrivKeySeed,
                       ECQV_e, eSize,
                       ECQV_r, sizeof(ECQV_r),
                       NULL, 0,
                       &ECPublicKeyVerify,
                       &ECPrivKeyVerify)) { errorflag = 1; return 0; }

    return CheckTestVectorBinary("Public key", ECPublicKeyChip.blob, ECPublicKeyChip.len, ECPublicKeyVerify.blob, ECPublicKeyVerify.len) &
           CheckTestVectorBinary("Private key", ECPrivKeyChip.blob, ECPrivKeyChip.len, ECPrivKeyVerify.blob, ECPrivKeyVerify.len);
}
//-------------------------------------------------------------------------------
int Test_FastECDSA_Step1(PKAlgorithm algid, int num)
{
    LogScreen("Step 1: ECDSA Fast preparation (preparing %d entries)\n", num);
    LogScreen("-----------------------------------------------------\n");
    if (!V2X_import_private_key(UserID, algid, KeyIndex, &ECPrvK_TestVectorECC256_Chip)){ errorflag = 1; return 0; }

    if (!V2X_ecdsa_fast_prepare(UserID, algid, KeyIndex, num)) { errorflag = 1; return 0; }
	LogScreen("ECDSA Fast preparation OK\n");
    return 1;
}
//-------------------------------------------------------------------------------
int Test_FastECDSA_Step2(PKAlgorithm algid)
{
    LogScreen("Step 2: ECDSA Fast signature:\n");
    LogScreen("-----------------------------------------------------\n");
    if (!V2X_import_private_key(UserID, algid, KeyIndex, &ECPrvK_TestVectorECC256_Chip)) { errorflag = 1; return 0; }

    // Message digest
    MessageSize = UTIL_hexStrToArray(TestVector_SHA_Message[0], MessageData, sizeof(MessageData));
    Crypto_Hash(MessageData, MessageSize, DigestData, DIGEST_SIZE); // Calculate SHA256 locally

    // Fast signature in V2X Prototype
    if (!V2X_ecdsa_fast_sign(UserID, algid,
                             KeyIndex,
                             DigestData,
                             DIGEST_SIZE,
                             Signature,
                             &SignatureSize)) return 0;
    // Verify fast signature on the host
    errorflag = VerifySignature(BYTE_TestVectorPubKeyECC256_Chip, sizeof(BYTE_TestVectorPubKeyECC256_Chip),
                                MessageData, MessageSize,
                                Signature, SignatureSize);

    HexDumpPort("Fast signature: ", Signature, SignatureSize);
    if (errorflag == 0) { LogScreen("Signature verified on host - OK\n\n"); return 1; }
    else                { LogError("Signature verification on host failed !\n\n"); return 0; }
}
//-------------------------------------------------------------------------------
int Test_SlowECDSA(PKAlgorithm algid)
{
    if (V2X_FirmwareVersion < 205) return 1; // Slow signing supported starting V2X Prototype ver.2.0.5

    LogScreen("Regular speed ECDSA test:\n");
    LogScreen("-----------------------------------------------------\n");
    if (!V2X_import_private_key(UserID, algid, KeyIndex, &ECPrvK_TestVectorECC256_Chip)) { errorflag = 1; return 0; }

    // Message digest
    MessageSize = UTIL_hexStrToArray(TestVector_SHA_Message[0], MessageData, sizeof(MessageData));
    Crypto_Hash(MessageData, MessageSize, DigestData, DIGEST_SIZE); // Calculate SHA256 locally

    // Regular speed signature in V2X Prototype
    if (!V2X_ecdsa_slow_sign(UserID, algid,
                             KeyIndex,
                             DigestData,
                             DIGEST_SIZE,
                             Signature,
                             &SignatureSize)) return 0;
    // Verify fast signature on the host
    errorflag = VerifySignature(BYTE_TestVectorPubKeyECC256_Chip, sizeof(BYTE_TestVectorPubKeyECC256_Chip),
                                MessageData, MessageSize,
                                Signature, SignatureSize);

    HexDumpPort("Regular speed signature: ", Signature, SignatureSize);
    if (errorflag == 0) { LogScreen("Signature verified on host - OK\n\n"); return 1; }
    else                { LogError("Signature verification on host failed !\n\n"); return 0; }
}
//-------------------------------------------------------------------------------
int Test_ECIES_test_vectors(PKAlgorithm algid)
{
    LogScreen("ECIES test vectors:\n");
    LogScreen("------------------------------------\n");

    for (i=0; i<sizeof(TestVector_ECIES_V) / sizeof(char*); i++)
    {
        // Load Test vectors
        RecipientPublicKeySize = UTIL_hexStrToArray(TestVector_ECIES_R[i], RecipientPublicKey, sizeof(RecipientPublicKey));
        RecipientPrivateKeySize = UTIL_hexStrToArray(TestVector_ECIES_r[i], RecipientPrivateKey, sizeof(RecipientPrivateKey));
        PlainDataSize = UTIL_hexStrToArray(TestVector_ECIES_k[i], PlainData,   sizeof(PlainData));
        ParmDataSize = UTIL_hexStrToArray(TestVector_ECIES_P[i], ParmData,  sizeof(ParmData));

        EphemeralPublicKeySize = UTIL_hexStrToArray(TestVector_ECIES_V[i], EphemeralPublicKey, sizeof(EphemeralPublicKey));
        EphemeralPrivateKeySize = UTIL_hexStrToArray(TestVector_ECIES_v[i], EphemeralPrivateKey, sizeof(EphemeralPrivateKey));
#if 0
        //==================================Verify Test vectors=================================
        // Verify test vectors using OpenSSL - Calculate ECIES locally and compare with test vectors
        if ((EncrDataSize = Crypto_ECIES_encrypt(RecipientPublicKey, RecipientPublicKeySize,
                            EphemeralPrivateKey, EphemeralPrivateKeySize,
                            ParmData, ParmDataSize,
                            PlainData,  PlainDataSize,
                            EncrData,
                            EncrTag,  &EncrTagSize)) == 0)
            { errorflag = 1; return 0; }
        if (!CheckTestVector("ECIES encrypt: data - OpenSSL", EncrData, EncrDataSize, TestVector_ECIES_C[i])) return 0;
        if (!CheckTestVector("ECIES encrypt: tag - OpenSSL", EncrTag, EncrTagSize, TestVector_ECIES_T[i])) return 0;
#endif
        //==================================ENCRYPT=============================================
        // V2X Prototype: Set Test vectors ephemeral keys to key ID 2999
        ECEphemeralPublicKey.len = EphemeralPublicKeySize;
        if (!V2X_import_public_key (UserID, algid, KeyID_Ephemeral, &ECEphemeralPublicKey)) { errorflag = 1; return 0; }
        ECEphemeralPrivateKey.len = EphemeralPrivateKeySize;
        if (!V2X_import_private_key(UserID, algid, KeyID_Ephemeral, &ECEphemeralPrivateKey)) { errorflag = 1; return 0; }

        // Encrypt in V2X Prototype
        ECIES_GenerateEphemeralKey = 0x8000; // Don't generate ephemeral key pair, use test vector imported above
        if (!V2X_ecies_encrypt(UserID, algid,
                               &ECRecipientPublicKey,
                               ParmData,  ParmDataSize,        // Key derivation parameter
                               PlainData, PlainDataSize,       // Data to encrypt
                               EncrData, &EncrDataSize,        // Encrypted data
                               EncrTag,  &EncrTagSize,         // Authentication Tag
                               EphemeralPublicKey, &EphemeralPublicKeySize))
            { errorflag = 1; return 0; }
        HexDumpPort("Encr.data: ", EncrData, EncrDataSize);
        HexDumpPort("Tag:       ", EncrTag, EncrTagSize);

        // Compare V2X Prototype results with test vectors
        if (!CheckTestVector("ECIES encrypt: data - test vector", EncrData, EncrDataSize, TestVector_ECIES_C[i])) return 0;
        if (!CheckTestVector("ECIES encrypt: tag - test vector", EncrTag, EncrTagSize, TestVector_ECIES_T[i])) return 0;

        //==================================DECRYPT=============================================
        // V2X Prototype: Set Test vectors recipient private key to current key index
        V2X_import_private_key(UserID, algid, KeyIndex, &ECRecipientPrivateKey); // Import private key for decryption

        // Decrypt in V2X Prototype
        if (!V2X_ecies_decrypt(UserID, algid,
                               KeyIndex,
                               &ECEphemeralPublicKey,
                               ParmData, ParmDataSize,
                               EncrData, EncrDataSize,
                               EncrTag,  EncrTagSize,
                               DecrData, &DecrDataSize))
            { errorflag = 1; return 0; }
        HexDumpPort("Decr.data: ", DecrData, DecrDataSize);

        // Compare V2X Prototype results with original plain data
        if (!CheckTestVectorBinary("Decr.data", DecrData, DecrDataSize, PlainData, PlainDataSize)) return 0;
    }
    return 1;
}
//-------------------------------------------------------------------------------
int Test_ECIES_encrypt_decrypt(PKAlgorithm algid)
{
    LogScreen("ECIES encrypt/decrypt:\n");
    LogScreen("------------------------------------\n");

    for (i=0; i<sizeof(TestVector_ECIES_V) / sizeof(char*); i++)
    {
        // Load Test vectors - recipient and test data
        RecipientPublicKeySize = UTIL_hexStrToArray(TestVector_ECIES_R[i], RecipientPublicKey, sizeof(RecipientPublicKey));
        RecipientPrivateKeySize = UTIL_hexStrToArray(TestVector_ECIES_r[i], RecipientPrivateKey, sizeof(RecipientPrivateKey));
        PlainDataSize = UTIL_hexStrToArray(TestVector_ECIES_k[i], PlainData,   sizeof(PlainData));
        ParmDataSize = UTIL_hexStrToArray(TestVector_ECIES_P[i], ParmData,  sizeof(ParmData));

        //==================================ENCRYPT=============================================
        // Encrypt in V2X Prototype
        ECIES_GenerateEphemeralKey = 0; // Generate ephemeral key pair
        if (!V2X_ecies_encrypt(UserID, algid,
                               &ECRecipientPublicKey,
                               ParmData,  ParmDataSize,        // Key derivation parameter
                               PlainData, PlainDataSize,       // Data to encrypt
                               EncrData, &EncrDataSize,        // Encrypted data
                               EncrTag,  &EncrTagSize,         // Authentication Tag
                               EphemeralPublicKey, &EphemeralPublicKeySize))
            { errorflag = 1; return 0; }
        HexDumpPort("Encr.data: ", EncrData, EncrDataSize);
        HexDumpPort("Tag:       ", EncrTag, EncrTagSize);

        //==================================DECRYPT=============================================
        // V2X Prototype: Set Test vectors recipient private key to current key index
        V2X_import_private_key(UserID, algid, KeyIndex, &ECRecipientPrivateKey); // Import private key for decryption

        // Decrypt in V2X Prototype
        if (!V2X_ecies_decrypt(UserID, algid,
                               KeyIndex,
                               &ECEphemeralPublicKey,
                               ParmData, ParmDataSize,
                               EncrData, EncrDataSize,
                               EncrTag,  EncrTagSize,
                               DecrData, &DecrDataSize))
            { errorflag = 1; return 0; }
        HexDumpPort("Decr.data: ", DecrData, DecrDataSize);

        // Compare V2X Prototype results with original plain data
        if (!CheckTestVectorBinary("Decr.data", DecrData, DecrDataSize, PlainData, PlainDataSize)) return 0;
    }
    return 1;
}
//-------------------------------------------------------------------------------
int Test_ECDSA_standard(PKAlgorithm algid)
{
    LogScreen("ECDSA standard sign:\n");
    LogScreen("------------------------------------\n");
    if (!V2X_import_private_key(UserID, algid, KeyIndex, &ECPrvK_TestVectorECC256_Chip)) { errorflag = 1; return 0; }
    if (!V2X_import_public_key(UserID, algid, KeyIndex, &ECPubK_TestVectorECC256_Chip)) { errorflag = 1; return 0; }
//              Crypto_ECC_SetPublicKey(ECPubK_TestVectorECC256_Chip.blob, ECPubK_TestVectorECC256_Chip.len);

    MessageSize = UTIL_hexStrToArray(TestVector_SHA_Message[0], MessageData, sizeof(MessageData));
    Crypto_Hash(MessageData, MessageSize, DigestData, DIGEST_SIZE); // Calculate SHA256 locally

    if (!V2X_ecdsa_sign(UserID, algid,
                         KeyIndex,
                         DigestData,
                         DIGEST_SIZE,
                         Signature,
                         &SignatureSize)) { errorflag = 1; return 0; }

    HexDumpPort("Signature: ", Signature, SignatureSize);

    if (VerifySignature(ECPubK_TestVectorECC256_Chip.blob, ECPubK_TestVectorECC256_Chip.len, //BYTE_TestVectorPubKeyECC256_Chip, sizeof(BYTE_TestVectorPubKeyECC256_Chip),
                        MessageData, MessageSize,
                        Signature, SignatureSize))
        { errorflag = 1;  LogError("Signature verification on the host failed !\n\n"); }
    else LogScreen("Signature verified on host - OK\n\n");

    LogScreen("ECDSA standard verify:\n");
    LogScreen("------------------------------------\n");
    Crypto_Hash(MessageData, MessageSize, DigestData, DIGEST_SIZE); // Calculate SHA256 locally

    if (V2X_ecdsa_verify(UserID, algid,
                             KeyIndex,
                             DigestData,
                             DIGEST_SIZE,
                             Signature,
                             SignatureSize))
        LogScreen("Signature verified OK\n");
    else { errorflag=1; LogError("Signature verification failed !\n"); return 0;}
    return 1;
}
//-------------------------------------------------------------------------------
int Test_SHA()
{
    LogScreen("SHA256 digest:\n");
    LogScreen("------------------------------------\n");
    for (i=0; i<sizeof(TestVector_SHA_Message) / sizeof(char*); i++)
    {
        // Load test vector data
        MessageSize = UTIL_hexStrToArray(TestVector_SHA_Message[i], MessageData, sizeof(MessageData));

        // Get digest from V2X Prototype
        if (!V2X_digest(UserID, 0x04, MessageData, MessageSize, DigestData, &DigestSize))
            { errorflag = 1; return 0; }

        HexDumpPort("Message: ", MessageData, MessageSize);
        HexDumpPort("SHA256:  ", DigestData, DigestSize);

        // Compare digest with test vectors
        if (!CheckTestVector("SHA256 test vector", DigestData, DigestSize, TestVector_SHA_Out[i])) return 0;

        // Verify OpenSSL - Calculate SHA256 locally and compare with test vectors
        Crypto_Hash(MessageData, MessageSize, TestData, DigestSize);
        if (!CheckTestVector("SHA256 OpenSSL", TestData, DigestSize, TestVector_SHA_Out[i])) return 0;
    }
    return 1;
}
//-------------------------------------------------------------------------------
int Test_HMAC()
{
    LogScreen("HMAC:\n");
    LogScreen("------------------------------------\n");
    for (i=0; i<sizeof(TestVector_HMAC_Key) / sizeof(char*); i++)
    {
        // Load test vector data
        TestHMAC_key.len = UTIL_hexStrToArray(TestVector_HMAC_Key[i], BYTE_TestHMAC_key, sizeof(BYTE_TestHMAC_key));
        MessageSize = UTIL_hexStrToArray(TestVector_HMAC_Msg[i], MessageData, sizeof(MessageData));

        // Verify OpenSSL - Calculate HMAC locally and compare with test vectors
        TestSize = Crypto_MAC(TestHMAC_key.blob, TestHMAC_key.len, ALG_HMAC, 0, MessageData, MessageSize, TestData);
        if (!CheckTestVector("HMAC OpenSSL", TestData, TestSize, TestVector_HMAC_Out[i])) return 0;

        // Write HMAC key into V2X Prototype NVM key info area (variable size)
        if (!V2X_import_public_key(UserID, 0, KeyID_HMAC, &TestHMAC_key)) { errorflag = 1; return 0; }

        // Calculate HMAC in V2X Prototype
        if (!V2X_HMAC(UserID, KeyID_HMAC, MessageData, MessageSize, DigestData, &DigestSize))
            { errorflag = 1; return 0; }
        HexDumpPort("HMAC: ", DigestData, DigestSize);

        // Compare V2X Prototype HMAC with test vectors
        if (!CheckTestVector("HMAC test vector", DigestData, DigestSize, TestVector_HMAC_Out[i])) return 0;
    }
    return 1;
}
//-------------------------------------------------------------------------------
int Test_ECDH(PKAlgorithm algid)
{
    LogScreen("ECDH key agreement:\n");
    LogScreen("------------------------------------\n");

    if (!V2X_import_private_key(UserID, algid, KeyIndex, &ECPrvK_TestVectorECC256_Chip)) { errorflag = 1; return 0; }

    if (!V2X_ecdh_derivation(UserID, algid,
                             KeyIndex,
                             &ECPubK_TestVectorECC256_Host, // Testvector: HostPublicKey = QCAVS
                             SharedSecret,
                             &SharedSecretSize)) { errorflag = 1; return 0; }
    if (SharedSecretSize != DIGEST_SIZE)
        { LogError("ERROR: Shared secret has incorrect size: len=%d\n", SharedSecretSize); errorflag=1; return 0; }
    HexDumpPort("Secret: ", SharedSecret, SharedSecretSize);

    DigestSize = Crypto_ECDH(0, ECPubK_TestVectorECC256_Host.blob, ECPubK_TestVectorECC256_Host.len,
                               ECPrvK_TestVectorECC256_Chip.blob, ECPrvK_TestVectorECC256_Chip.len,
                               DigestData); // Calculate ECDH locally and compare

    return CheckTestVectorBinary("ECDH OpenSSL", SharedSecret, SharedSecretSize, DigestData, DigestSize);
}
//-------------------------------------------------------------------------------
int Test_KDF2()
{
    LogScreen("KDF2:\n");
    LogScreen("------------------------------------\n");
    for (i=0; i<sizeof(TestVector_KDF2_SS) / sizeof(char*); i++)
    {
        // Load test vector data
        SharedSecretSize = UTIL_hexStrToArray(TestVector_KDF2_SS[i], SharedSecret, sizeof(SharedSecret));
        MessageSize = UTIL_hexStrToArray(TestVector_KDF2_KDP[i], MessageData, sizeof(MessageData));

        // Verify OpenSSL - Calculate KDF2 locally and compare with test vectors
        Crypto_KDF(SharedSecret, SharedSecretSize, MessageData, MessageSize, TestVector_KDF2_Len[i], TestData);
        if (!CheckTestVector("KDF2 OpenSSL", TestData, TestVector_KDF2_Len[i], TestVector_KDF2_Out[i])) return 0;

        // Calculate KDF2 in V2X Prototype
        // Send 80 52 00 00 Lc 83 || Len || Shared Secret || 84 || Len || KDP
        if (!V2X_KDF2(UserID, SharedSecret, SharedSecretSize, MessageData, MessageSize, TestVector_KDF2_Len[i], DigestData)) { 
			errorflag = 1;
			return 0;
		}
        HexDumpPort("KDF2: ", DigestData, TestVector_KDF2_Len[i]);

        // Compare KDF2 with test vectors
        if (!CheckTestVector("KDF2 test vector", DigestData, TestVector_KDF2_Len[i], TestVector_KDF2_Out[i])) return 0; 
    }
    return 1;
}
//-------------------------------------------------------------------------------
void TestEcho(int start, int variable_delay)
{
    int trans_num=1, datasize, delay = 0;
    BYTE test_data[MAX_DATA_SIZE];

    for (trans_num=1, errors_num=0; trans_num <= 100000; trans_num++)
    {
      for (i = 0; i < MAX_DATA_SIZE; i++)
          test_data[i] = (BYTE)(((i+trans_num) >> 8) + ((i+trans_num) & 0xFF));   // Prepare data for APDU

      for (datasize=start, errors_num=0; datasize < /*128*/ MAX_DATA_SIZE; datasize++)
      {
        if (variable_delay) delay = datasize;
        if (!V2X_echo(UserID, test_data, datasize, delay, RESP_APDU, &RESP_APDU_size)) {
            errors_num++;
            if (Save_LogLevel > 1) goto err_stop1; // Stop after any error if debugging
        }
        if (RESP_APDU_size == 0) {
            LogError("\nERROR:                                                              Step %d\n", datasize);
            errors_num++;
            if (Save_LogLevel > 1) goto err_stop1; // Stop after any error if debugging
        }
        else {
            if (RESP_APDU_size != datasize || memcmp(RESP_APDU, test_data, datasize) != 0)
            {
                LogError("\nERROR:                                                              Step %d\n", datasize);
                HexDump("Sent:     ", (BYTE*)test_data, datasize);
                HexDump("Received: ", RESP_APDU, RESP_APDU_size);
                errors_num++;
                if (Save_LogLevel > 1) goto err_stop1; // Stop after any error if debugging
            }
            else LogScreen("Data size:%5d  Count:%6d  Errors:%4d  Time:%5d ms\r", datasize, trans_num, errors_num, Stat_Time_finish - Stat_Time_start);
        }
        if (checkKey() == ESC_KEY) goto err_stop1;  // Stop cycle if ESC key pressed
      }
    }
err_stop1:
    LogScreen("\n=========================================================\n");
    LogScreen("Data size:%5d  Count:%6d  Errors:%4d\r", datasize, trans_num, errors_num);
    if (errors_num) errorflag=1;
}

//-------------------------------------------------------------------------------
// HSM initialization: ask file encryption password, load and
// authenticate Transport key, load from file and program to HSM all
// required User keys/passwords, change HSM life cycle to Operation
//-------------------------------------------------------------------------------
int Initialize_HSM(void)
{
	int user;
	int lcycle;
	char versionstr[256];
	BYTE TransportKeyID[KEYIDSIZE];     // Current HSM's Transport Key ID
	BYTE TransportKey[USER_KEY_SIZE + 1]; // Current HSM's Transport Key
	int  TransportKeySize;

	if ((V2X_FirmwareVersion = V2X_firmware_version(0, versionstr)) == 0) { errorflag = 1; return 0; }
	if (V2X_FirmwareVersion < 200) return 1; // Secure session not supported in firmware < 2.0.x

	// Check HSM life cycle state (initialization is required if HSM is not in Operation state)
	if ((lcycle = V2X_get_lifecycle_state(0)) == LIFECYCLE_OPERATION) {
		LogScreen("HSM is already in life cycle OPERATION. Initialization not required.\n");
		return 1;
	}
	// Retrieve current Transport key ID from HSM
	if (!V2X_GetKeyID(0, 0, TransportKeyID)) { errorflag = 1; return 0; }

	// Enter password on the keyboard if it wasn't entered before
	if (!Ask_Password(PASSWORD_PROMPT, UtilPassword)) { errorflag = 1; return 0; }

	// Load Transport key from file on the host encrypted with utility password
	if (!V2X_LoadUserKey(TransportKeyID, UtilPassword, TransportKey, &TransportKeySize)) { errorflag = 1; return 0; }

	LogScreen("Authenticate with Transport key and start secure session\n");
	if (!V2X_Open(0, TransportKey, TransportKeySize)) { errorflag = 1; return 0; }

	if (lcycle == LIFECYCLE_MANUFACTURING) {
		LogScreen("Set HSM life cycle INITIALIZATION\n");
		if (V2X_change_life_cycle(0, LIFECYCLE_INITIALIZATION) == 0) { errorflag = 1; return 0; }
	}
	for (user = 0; user < MAX_USERS; user++) {
		if (UserKeySize[user]) {
			LogScreen("Set/change User %d key\n", user);
			if (!V2X_change_user_key(0, CLA_HMAC, user, UserKey[user], UserKeySize[user])) { errorflag = 1; return 0; }
		}
	}
	LogScreen("Set HSM life cycle OPERATION\n");
	if (V2X_change_life_cycle(0, LIFECYCLE_OPERATION) == 0) { errorflag = 1; return 0; }

	V2X_Close(0); // Close Transport key session with HSM
	if (!errorflag) LogScreen("Initialized - OK\n");
	return 1;
}

//-------------------------------------------------------------------------------
int Test_All_V2X(PKAlgorithm algid)
{
    Crypto_init(ConvertAlgID(algid));

    if (!V2X_keygen(UserID, algid, KeyIndex, &ECRecipientPublicKey)) return 0;    LogScreen("\n");
    if (!Test_ECQV_Reception(algid))        return 0;    LogScreen("\n");
    if (!Test_FastECDSA_Step1(algid, 50))   return 0;    LogScreen("\n");
    if (!Test_FastECDSA_Step2(algid))       return 0;    LogScreen("\n");
    if (!Test_SlowECDSA(algid))             return 0;    LogScreen("\n");
    if (!Test_ECIES_test_vectors(algid))    return 0;    LogScreen("\n");
    if (!Test_ECIES_encrypt_decrypt(algid)) return 0;    LogScreen("\n");
    if (!Test_ECDSA_standard(algid))        return 0;    LogScreen("\n");
    if (!Test_SHA())                        return 0;    LogScreen("\n");
    if (!Test_HMAC())                       return 0;    LogScreen("\n");
    if (!Test_ECDH(algid))                  return 0;    LogScreen("\n");
    if (!Test_KDF2())                       return 0;    LogScreen("\n");

    Crypto_close();
    return 1;
}

//-------------------------------------------------------------------------------
//	Execute a command represented as a Hex text string (CLA INS P1 P2 Lc Data Le).
//	Send command APDU receive response APDU, check returned SW1 SW2 code.
//-------------------------------------------------------------------------------
int SendAPDU(char *str_apdu, int timeout)
{
	int ret;
	int APDUsize = UTIL_hexStrToArray(str_apdu, APDUbuffer, sizeof(APDUbuffer));
	if (APDUsize == 0) {
		LogError("\nERROR: Invalid command APDU: [%s]\n", str_apdu ? str_apdu : "Null");
		return 0;
	}
	ret = V2X_send_apdu(UserID, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, timeout);
	if (ret && RESP_APDU_size >= 2 &&
		RESP_APDU[RESP_APDU_size - 2] == 0x90 &&
		RESP_APDU[RESP_APDU_size - 1] == 0x00)
		return 1;
	LogError("\nERROR: APDU '%s' failed. SW1SW2=%04X\n\n", str_apdu, SW1SW2);
	return 0;
}

//-------------------------------------------------------------------------------
// Write Firmware file to HSM
//-------------------------------------------------------------------------------
int Write_Firmware(char *binfilename)
{
	BYTE *pFirmware;
	int filesize, blocksize, ret = 0;
	int  adr;

	pFirmware = LoadFromFile(binfilename, NULL, &filesize);
	if (pFirmware == NULL || filesize == 0) { LogError("\nERROR: Invalid Firmware file: \n %s\n\n", binfilename); goto upload_exit; }

	for (adr = 0; adr < filesize; adr += NVM_UPLOAD_BLOCK_SIZE)
	{
		if (adr + NVM_UPLOAD_BLOCK_SIZE > filesize)
			blocksize = filesize % NVM_UPLOAD_BLOCK_SIZE;
		else                                        blocksize = NVM_UPLOAD_BLOCK_SIZE;

		if (!V2X_WriteFirmware(UserID, adr / NVM_PAGE_SIZE, pFirmware + adr, blocksize))
		{
			LogScreen("\nERROR: Firmware writing failed\n\n"); goto upload_exit;
		}
		if (checkKey() == ESC_KEY) { LogScreen("\nWARNING: Firmware writing interrupted\n"); goto upload_exit; }
		Log(".");
	}
	LogScreen("\nFirmware file written: %s\n", binfilename);
	ret = 1;
upload_exit:
	SAFE_FREE(pFirmware);
	return ret;
}

//-------------------------------------------------------------------------------
// Download and install HSM firmware update
//-------------------------------------------------------------------------------
int Program_HSM_Firmware(char *binfilename)
{
	char str_firmware[256];
	int ret = 0;

	UserID = 0;
	//- - - - - - - - - - - - - - - - - - - - - - - -
	if ((V2X_FirmwareVersion = V2X_firmware_version(UserID, str_firmware)) == 0)
	{
		LogError("\nERROR: Getting old HSM firmware version failed\n\n");
		goto ProgFW_exit;
	}
	LogScreen("Old HSM Firmware version: %s\n\n", str_firmware);

	//if (!HSM_GetKeyID(0, 0, KeyIndex))
	//	goto ProgFW_exit; // Retrieve current Transport key ID from HSM
	//// Enter password on the keyboard if it wasn't entered before
	//if (!Ask_Password(PASSWORD_PROMPT, UtilPassword))
	//	goto ProgFW_exit;

	//// Load User key from file on the host encrypted with utility password
	//if (!HSM_LoadUserKey(KeyIndex, UtilPassword, AuthKey, &AuthKeySize))
	//	goto ProgFW_exit;

	if (!GetUserKey(UserID)) { errorflag = 1; return 0; }

	if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0)
		goto ProgFW_exit;


	//   if (!HSM_Open(0, AuthKey, AuthKeySize))
	//{
	//	LogError("\nERROR: Transport Key authentication failed\n\n");
	//	goto ProgFW_exit;
	//}

	//   LogScreen("Resetting HSM ...\n");
	//   SendAPDU("80 F1 00 01 10", 100);
	//   Sleep(1000);

	//if (!HSM_Open(0, AuthKey, AuthKeySize)) { LogError("\nERROR: Transport Key authentication failed\n\n"); goto ProgFW_exit; }
	//- - - - - - - - - - - - - - - - - - - - - - - -
	//

	LogScreen("Writing new firmware file: %s\n", binfilename);
	if (!Write_Firmware(binfilename)) return 0;

	//LogScreen("Verifying new firmware file: \n %s\n", binfilename);
	//if (!Verify_Firmware(binfilename)) return 0;

	//
	//- - - - - - - - - - - - - - - - - - - - - - - -
	LogScreen("Verifying firmware signature ...\n");
	if (!SendAPDU("80 F4 00 00 10", 100))
	{
		LogError("\nERROR: Firmware signature verification failed\n\n");
		goto ProgFW_exit;
	}

	//	HSM_Close(0); // Close Transport key session with HSM

	LogScreen("Switch to SPI Flashloader part ...\n");
	SessionActive[0] = 0;
	{
		BYTE ReactivateSPIFlashLoaderAPDU[] = { 0xC2, 0xA0, 0x01, 0x00, 0x10 };
		if (!V2X_send_apdu(UserID, ReactivateSPIFlashLoaderAPDU, sizeof(ReactivateSPIFlashLoaderAPDU), RESP_APDU, &RESP_APDU_size, 1000))
		{
			errorflag = 1;
			return 0;
		}
	}
//	HexDump("Response: ", RESP_APDU, 2);

	Sleep(2000);

	if ((V2X_FirmwareVersion = V2X_firmware_version(UserID, str_firmware)) == 0)
	{
		LogError("\nERROR: Getting SPI flashloader version failed\n\n");
		goto ProgFW_exit;
	}

	LogScreen("SPI Flashloader version: %s\n\n", str_firmware);

	LogScreen("Installing new firmware ...\n");
	if (!SendAPDU("C2 F4 00 00 10", 2000))
	{
		LogError("\nERROR: Install firmware failed\n\n"); /*goto ProgFW_exit;*/
	}

	BYTE GetDataAPDU[] = { 0x80, 0xCA, 0x00, 0xFE, 0x10 };
	if (!V2X_send_apdu(UserID, GetDataAPDU, sizeof(GetDataAPDU), RESP_APDU, &RESP_APDU_size, 100))
	{
		LogError("\nERROR: Getting new firmware CRC failed\n\n");
		goto ProgFW_exit;
	}

	LogScreen("Restarting HSM  - switch back to updated V2X Prototype ...\n");
	if (!SendAPDU("C2 A0 01 01 10", 2000))
	{
		LogError("\nERROR: HSM restart failed\n\n");
		goto ProgFW_exit;
	}

	Sleep(2000);

	if ((V2X_FirmwareVersion = V2X_firmware_version(UserID, str_firmware)) == 0)
	{
		LogError("\nERROR: Getting new HSM firmware version failed\n\n");
		goto ProgFW_exit;
	}
	LogScreen("New HSM Firmware version: %s\n\n", str_firmware);

	if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0)
	{
		LogError("\nERROR: Transport key authentication with new firmware failed\n\n");
		goto ProgFW_exit;
	}

	LogScreen("Installing new flashloader ...\n");
	if (!SendAPDU("80 F4 01 00 10", 1000))
	{
		LogError("\nERROR: Install new flashloader failed\n\n");
		goto ProgFW_exit;
	}

	V2X_Close(0); // Close Transport key session with HSM
	ret = 1;
	//- - - - - - - - - - - - - - - - - - - - - - - -
ProgFW_exit:

		return ret;
}

//-------------------------------------------------------------------------------
//           Main
//-------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
	// Find first SPI host adapter, open it and configure SPI host adapter
	// (In the case, the function does nothing)
	if (V2X_Initialize() == 0) goto err_exit;

	// Initialize host crypto library
	Crypto_init(ConvertAlgID(AlgID));

#ifdef _DEBUG
	// hook for debugging - wait to attach process!
	LogScreen("........... Press any key after attaching debugger ...............\n");
	getKey();   // Wait until any key pressed
#endif

	// Buffer for full command interface line, limited to 4096 byte
	char cCommandBuffer[256] = { 0x00 };
	command_structure commands[128];
	int count = 0;
	int JJ = 0;
	memset(commands, '\x00', sizeof(commands));


	// Display menu
	LogScreen("**************************************\n");
	LogScreen("*                                    *\n");
        LogScreen("*   INFINEON V2XTOOL (Version %s)   *\n", VERSION);
        LogScreen("*                                    *\n");
        LogScreen("**************************************\n");
	LogScreen("*  Type 'help' for a list available  *\n");
	LogScreen("*    commands or 'quit' for exit.    *\n");
        LogScreen("**************************************\n");

	//if (LogLevel >= 2) LogScreen("\n!! APDU debug mode is enabled\n");
	//if (LogLevel == 3) LogScreen("!! Deep SPI protocol debug mode is enabled\n");
	LogScreen("\nLogLevel: %d\n", LogLevel);

	// if a file was passed via the command line: read in!
	if (argc > 1)
	{
		// A file was given as input ... read in!
		char CDir[1024] = { 0x00 };
		// get current directory to assemble full path of file
		char * cDir = (char*) getcwd(CDir, sizeof(CDir));
		strcat(cDir, "/");
		strcat(cDir, argv[1]);

		printf("\n-> Reading file %s ...\n", cDir);

		char* mybuffer = NULL;	// will be allocated in "read_file()"
		if (read_file(cDir, &mybuffer) == 0)
			return -1;

		// remove all \t \r
		char spanset1[] = "\t\r";
		stringRemoveChars(mybuffer, spanset1);

		// separate comments
		count = parse_comments(mybuffer, commands, 128);

		// free allocated memory
		free(mybuffer);
	}




	// Prompt loop:
	do {
		printf("\n> "); //Prompt

		i = 0;


		if (argc > 1)
		{
			memset(&(cCommandBuffer[0]), '\x00', sizeof(cCommandBuffer));

			if (JJ < count)
				strcpy(cCommandBuffer, commands[JJ].command);

			if (JJ == count)
				return 0;
			else
				JJ++;
		}
		else
		{
wait_for_input:
			memset(&(cCommandBuffer[0]), '\x00', sizeof(cCommandBuffer));
			int s = 0;

			do
			{
				cCommandBuffer[s] = getchar();      //getch(): does not echo automatically -> LogScreen("%s", &(cCommandBuffer[i]));, no implicit buffer of issued commands!!!; 0x0d required

				if (cCommandBuffer[s] == EOF) {
					return 0;
				}

				s++;

			} while ((cCommandBuffer[s - 1] != 0x0a) &&
				(s < sizeof(cCommandBuffer) - 1));
		} // end of if (argc > 1)

		 // remove all \t \n
		char spanset[] = "\t\n";
		stringRemoveChars(cCommandBuffer, spanset);

		// empty command (could be commented)
		if (strlen(cCommandBuffer) == 0)
		{
			if (argc > 1) {
				continue;
			}
			else
				goto wait_for_input;
		}


#ifdef _DEBUG
		printf("Final command:");
		printf(cCommandBuffer);
		printf("\n");
#endif
		//// convert to upper - no due to linux
		//int k = 0;
		//for (k = 0; k < (int)strlen(cCommandBuffer); k++)
		//	cCommandBuffer[k] = toupper(cCommandBuffer[k]);

		char comment_str[] = "#";
		char *pres;
		pres = strstr(cCommandBuffer, comment_str);
		if (pres != NULL) {
			int result = (int)(pres - cCommandBuffer);
			strncpy(cCommandBuffer, cCommandBuffer, result);
		}

		errorflag = 0;

		//Main command ... limited to 24 chars + trailing \0
		char cCommand[25] = { 0x00 };
fileinput:
		sscanf(&(cCommandBuffer[0]), "%24s", cCommand);

		// pre-sorting
		char cCommandArg[20][2 * MAX_APDU_SIZE] = { 0x00 };
		int iOffset = strlen (cCommand) + 1;
		int iScanned = 0;

		// first argument may always be a password
		iScanned = sscanf(&(cCommandBuffer[iOffset]), "-psw %32s", UtilPassword);

		if (iScanned > 0)
			iOffset += strlen(UtilPassword) + 5 /*"-PSW"*/ + 1;

		i = 0;
		iScanned = 0;
		do
		{
			iScanned = sscanf(&(cCommandBuffer[iOffset]), "%s", cCommandArg[i]);
			iOffset += strlen(cCommandArg[i]) + 1;
			i++;

		} while (iScanned > 0);

		iScanned = ( i - 1 );

		// Big decision tree
		if (strcmp(cCommand, "help") == 0) {
			LogScreen("\nList of all available commands\n");
			LogScreen("--------------------------------\n");

			LogScreen("help        ... print a list of all available commands (and usage)\n");
			LogScreen("init        ... creating fresh key files and setting SLS37 V2X Prototype from MANUFACTURING to INITIALIZATION mode.\n");
			LogScreen("open        ... open secure session by authenticating with user key [0 ... 7] and start secure session\n");
			LogScreen("close       ... destroy session keys\n");
			LogScreen("updatefw    ... upload encrypted and signed *.bin firmware update file to the chip\n");
			LogScreen("testspi     ... test SPI stability with V2X_echo() command\n");
			LogScreen("info        ... show version string, life cycle state, access conditions, secure session information, etc.\n");
			LogScreen("printnvm    ... dump content of key slots (public keys) and file slots\n");
			LogScreen("writefile   ... write data (raw bytes) into a specified file slot; specify 0 or NULL for zeroizing a file\n");
			LogScreen("readfile    ... reads a file slots\n");
			LogScreen("importkey   ... import ECC public/private key pair into key slot (parameter: slot id, private key)\n");
			LogScreen("genkey      ... generate a ECC key pair and store it in one key slot [0 ... 2999]\n");
			LogScreen("delkey      ... delete one or all key slots\n");
			LogScreen("setac       ... set a specific Acces Condition Byte (either for key slots, user passwords / keys or the life cycle transition AC bytes)\n");
			LogScreen("randkeyfile ... Generate encrypted key file using the chip's TRNG\n");
			LogScreen("pwkeyfile   ... Generate encrypted key file with a symbolic password\n");
			LogScreen("hexkeyfile  ... Generate encrypted key file with a hex string\n");
			LogScreen("sendcmd     ... send APDU command (\"e.g. 80CA000000\") and receive response.\n");
			LogScreen("reset       ... \"Factory Reset\": delete all key slots, file slots, return to MANUFACTURING state, return to default access conditions (if permitted)\n");
			LogScreen("testsha     ... run SHA256 test vectors (+print timing)\n");
			LogScreen("testhmac    ... run HMAC test vectors (+print timing)\n");
			LogScreen("prepecdsa   ... prepare ECDSA seedlings for specific key slots (+print timing)\n");
			LogScreen("testecdsa   ... run ECDSA test vectors (+print timing)\n");
			LogScreen("testecdh    ... run ECDH test vector (+print timing)\n");
			LogScreen("testecqv    ... run ECQV Reception test (+print timing)\n");
			LogScreen("testecies   ... run ECIES test vectors (+print timing)\n");
			LogScreen("testaes     ... run AES test vectors (+print timing)\n");
			LogScreen("testx       ... test all v2x commands\n");
			LogScreen("q or quit   ... exit the program\n");

			continue;
		}
		else if ((strcmp(cCommand, "q") == 0) || (strcmp(cCommand, "quit") == 0) || (strcmp(cCommand, "exit") == 0)) {
			LogScreen("Exiting .....\n");
			goto err_exit;
		}
		else if (strcmp(cCommand, "open") == 0) {
			LogScreen("Open secure session by authenticating with user X\n");
			LogScreen("------------------------------------\n");

			if (iScanned > 1)
				LogScreen("\nIllegal arguments detected - will be ignored! \n Supported: the index of the user to be used for authentication [0 ... 7]!\n");

BYTE ConvertAlgID(BYTE alg);			// First argument (optional): UserID
			if (strlen(cCommandArg[0]) == 0) {
				LogScreen("\nPlease specify the index of the user to be used for authentication [0 ... 7]!\n");
				scanf("%d", &UserID);
			}
			else {
				UTIL_hexStrToArray(cCommandArg [0], (BYTE *)&UserID, 1);
			}

			if (!GetUserKey(UserID)) { errorflag = 1; break; }
			if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) break;

			LogScreen("User %d: session opened successfully\n", UserID);
			continue;
		}
		else if (strcmp(cCommand, "close") == 0) {
			LogScreen("Destroy all session keys\n");
			LogScreen("------------------------------------\n");

			if (iScanned > 0)
				LogScreen("\nIllegal arguments detected - will be ignored! \n");


			for (i = 0; i < MAX_USERS; i++)
				if (V2X_Close(i) == 0) break;

			memset(SessionActive, 0, sizeof(SessionActive));
			memset(SessionID, 0, sizeof(SessionID));

			LogScreen("All sessions closed successfully\n");
			continue;
		}
		else if (strcmp(cCommand, "testx") == 0) {
			Test_All_V2X(ECDSA_NISTP256_WITH_SHA256); // All V2X commands test
			continue;
		}
		else if (strcmp(cCommand, "testspi") == 0) {
			LogScreen("Running SPI communication stability test 100K times ... (Press ESC to stop)\n");
			LogScreen("----------------------------------------------------------------------------\n");

			if (iScanned > 0)
				LogScreen("\nIllegal arguments detected - will be ignored! \n");

			UserID = 0; // No secure session
			V2X_FirmwareVersion = V2X_firmware_version(0, strng);
			Save_LogLevel = LogLevel;
			LogLevel = 1;
			TestEcho(1, 0);
			LogLevel = Save_LogLevel;

			LogScreen("SPI test passed successfully\n");
			continue;
		}
		else if (strcmp(cCommand, "info") == 0) {
			LogScreen("V2X Prototype information:\n");
			LogScreen("------------------------------------\n");

			if (iScanned > 0)
				LogScreen("\nIllegal arguments detected - will be ignored! \n");

			if ((V2X_FirmwareVersion = V2X_firmware_version(UserID, strng)) == 0) { errorflag = 1; break; }
			LogScreen("Firmware version: %s\n\n", strng);

			if (i = V2X_get_lifecycle_state(UserID))
				LogScreen("Life cycle state: %02X - %s\n\n", i, (i == 1) ? "Manufacturing" :
				((i == 4) ? "Initialization" :
					((i = 0x10) ? "Operation" : "ERROR")));
			eSize = V2X_GetMemoryInfo(UserID);
			LogScreen("Total Private key slots in HSM : %d\n\n", eSize);

			if (!V2X_GetChipInfo(UserID, ChipID)) { errorflag = 1; break; }
			HexDump("V2X Prototype serial number: ", ChipID, 12);

			BYTE GetDataAPDU[] = { 0x80, 0xCA, 0x00, 0xFE, 0x10 };
			if (!V2X_send_apdu(UserID, GetDataAPDU, sizeof(GetDataAPDU), RESP_APDU, &RESP_APDU_size, 100))
				break;
			HexDump("OS CRC:            ", RESP_APDU, 4);

			if (!V2X_GetKeyID(UserID, 0, UserKeyID[0])) break;
			HexDump("Transport key ID:  ", UserKeyID[0], KEYIDSIZE);

			if (!V2X_GetKeyID(UserID, 1, UserKeyID[1])) break;
			HexDump("Admin key ID:      ", UserKeyID[1], KEYIDSIZE);

			for (i = 2; i<8; i++) {
				if (!V2X_GetKeyID(UserID, i, UserKeyID[i])) break;
				LogScreen("User %d key ID:     ", i);
				HexDump("", UserKeyID[i], KEYIDSIZE);
			}
			if (!V2X_GetKeyID(UserID, 0xC3, FwUpdateKeyID)) break;
			HexDump("V2X Prototype Firmware update encryption key ID:  ", FwUpdateKeyID, KEYIDSIZE);
			if (!V2X_GetKeyID(UserID, 0xC6, FwCApublicKeyID)) break;
			HexDump("V2X Prototype Firmware signing CA public key ID:  ", FwCApublicKeyID, KEYIDSIZE);

			LogScreen("Information retrieved successfully\n");
			continue;
		}
		else if (strcmp(cCommand, "genkey") == 0) {
			LogScreen("Generate ECC key pair:\n");
			LogScreen("------------------------------------\n");

			if (iScanned > 1)
				LogScreen("\nIllegal arguments detected - will be ignored! \n Supported: the index of the key to be generated!\n");

			// First argument (optional): KeyIndex
			if (strlen(cCommandArg[0]) != 0) {
				KeyIndex = atoi((const char*)&(cCommandArg[0]));
			}
			else {
				KeyIndex = 0;
			}

			if (V2X_keygen(UserID, AlgID, KeyIndex, &ECRecipientPublicKey))
				HexDump("Public key: ", ECRecipientPublicKey.blob, ECRecipientPublicKey.len);

			LogScreen("Key %d created successfully\n", KeyIndex);
			continue;
		}
		else if (strcmp(cCommand, "delkey") == 0) {
			LogScreen("Erase key slot:\n");
			LogScreen("------------------------------------\n");

			if (iScanned > 1)
				LogScreen("\nIllegal arguments detected - will be ignored! \n Supported: the index of the key to be erased!\n");

			// First argument (optional): kIndex
			if (strlen(cCommandArg[0]) != 0) {
				kIndex = atoi((const char*)&(cCommandArg[0]));
			}
			else {
				kIndex = 0;
			}

			if (V2X_DeletePrivateKey(UserID, kIndex))
				LogScreen("%d: erased\n", kIndex);

			LogScreen("Key %d erased successfully\n", kIndex);
			continue;
		}
		else if (strcmp(cCommand, "reset") == 0) {
			LogScreen("Zeroize V2X Prototype keys, return to Manufacturing state\n");
			LogScreen("---------------------------------------------------------\n");

			if (iScanned > 0)
				LogScreen("\nIllegal arguments detected - will be ignored! \n");

			UserID = 1; // Authenticate Admin - no other choice
			if (!GetUserKey(UserID)) { errorflag = 1; return 0; }

			if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) break;
			if (V2X_DeletePrivateKey(UserID, 0xFFFF))
				LogScreen("V2X Prototype zeroized\n");
		}
		else if (strcmp(cCommand, "printnvm") == 0) {
			LogScreen(" Slot          Public key\n");
			LogScreen("---------------------------------------------------------------------\n");

			if (iScanned > 0)
				LogScreen("\nIllegal arguments detected - will be ignored! \n");

			Save_LogLevel = LogLevel; Save_LogLevelFile = LogLevelFile;
			LogLevel = 0; LogLevelFile = 0;

			for (kIndex = 1; kIndex <= ECC_MAX_KEY_SLOT; kIndex++) {
				char str[20] = { 0x00 };
				V2X_export_private_key(UserID, kIndex, &ECPrivKeyChip);
				if (!V2X_export_public_key(UserID, kIndex, &ECEphemeralPublicKey)) { errorflag = 1; break; }

				LogLevel = Save_LogLevel; LogLevelFile = Save_LogLevelFile;
				if (ECPrivKeyChip.len > 2) {
					sprintf(str, "%4d: Private  ", kIndex);
					HexDump(str, ECPrivKeyChip.blob, ECPrivKeyChip.len);
				}
				if (ECEphemeralPublicKey.len > 2) {
					sprintf(str, "%4d: Public   ", kIndex);
					HexDump(str, ECEphemeralPublicKey.blob, ECEphemeralPublicKey.len);
				}
				LogLevel = 0; LogLevelFile = 0;
			}
			LogLevel = Save_LogLevel; LogLevelFile = Save_LogLevelFile;
		}
		else if (strcmp(cCommand, "testsha") == 0) {
			Test_SHA();
		}
		else if (strcmp(cCommand, "testhmac") == 0) {
			Test_HMAC();
		}
		else if (strcmp(cCommand, "prepecdsa") == 0) {

			if (iScanned > 1)
				LogScreen("\nIllegal arguments detected - will be ignored! \n Supported: \'l\' (for fast signature speed test) or the number of slots to be prepared!\n");
			eSize = 5; // default value to be prepared
			if (strlen(cCommandArg[0]) > 0)
			{
				if (cCommandArg[0][0] == 'l')
				{
					LogScreen("Fast signature test ... (Press ESC to stop)\n");
					LogScreen("------------------------------------------------------------\n");

					Save_LogLevel = LogLevel;
					LogLevel = 1;

					if (!Test_FastECDSA_Step1(AlgID, 50)) break;
					if (!Test_FastECDSA_Step2(AlgID)) break;

					LogScreen("Speed test:\n");
					Test_Time = 0;
					Test_Time_Min = 1000;
					Test_Time_Max = 0;
					for (trans_num = 0, errors_num = 0; trans_num < 100; trans_num++)
					{
						if (!V2X_ecdsa_fast_sign(UserID, AlgID,
							KeyIndex,
							DigestData,
							DIGEST_SIZE,
							Signature,
							&SignatureSize)) errors_num++;
						else if (VerifySignature(BYTE_TestVectorPubKeyECC256_Chip, sizeof(BYTE_TestVectorPubKeyECC256_Chip),
							MessageData, MessageSize,
							Signature, SignatureSize)) errors_num++;

						LogScreen("Test:%5d  Errors:%4d  Time:%5d ms\n", trans_num + 1, errors_num, (unsigned int)(Stat_Time_finish - Stat_Time_start));

						Test_Time += (uint64_t)(Stat_Time_finish - Stat_Time_start);
						if (Stat_Time_finish - Stat_Time_start > Test_Time_Max) Test_Time_Max = (uint64_t)(Stat_Time_finish - Stat_Time_start);
						if (Stat_Time_finish - Stat_Time_start < Test_Time_Min) Test_Time_Min = (uint64_t)(Stat_Time_finish - Stat_Time_start);

						if (checkKey() == ESC_KEY) break;  // Stop cycle if ESC key pressed
					}
					LogScreen("\n=========================================================\n");
					LogScreen("Errors:%4d  Min.time:%5d ms  Max.time:%5d ms  Average:%5d ms\r",
						errors_num, (unsigned int)Test_Time_Min, (unsigned int)Test_Time_Max, (unsigned int)((Test_Time_Max + Test_Time_Min) / 2));

					if (errors_num) errorflag = 1;

					LogLevel = Save_LogLevel;
					continue;
				}
				else
					eSize = atoi(&(cCommandBuffer[10]));
			}
			else {
				LogScreen("Enter number of slots to prepare: ");
				scanf("%d", &eSize);
			}

			Test_FastECDSA_Step1(AlgID, eSize);
		}
		else if (strncmp(cCommandBuffer, "testecdsa", 9) == 0) {
			Test_FastECDSA_Step2(AlgID);
			Test_ECDSA_standard(AlgID);
		}
		else if (strncmp(cCommandBuffer, "testecdh", 8) == 0) {
			Test_ECDH(AlgID);
		}
		else if (strncmp(cCommandBuffer, "testecqv", 8) == 0) {
			Test_ECQV_Reception(AlgID);
		}
		else if (strncmp(cCommandBuffer, "testecies", 9) == 0) {
			Test_ECIES_test_vectors(AlgID);
			Test_ECIES_encrypt_decrypt(AlgID);
		}
		else if (strncmp(cCommandBuffer, "testaes", 7) == 0) {
			LogScreen("AES test - encrypt and decrypt\n");
			LogScreen("------------------------------------------------------------\n");

			UserID = 1; // Authenticate Admin
			if (!GetUserKey(UserID)) { errorflag = 1; break; }
			if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) break;

			for (TestSize = 1; TestSize <= MAX_DATA_SIZE - 16; TestSize++)
			{
				if (checkKey() == ESC_KEY) continue;  // Stop cycle if ESC key pressed

				for (i = 0; i < TestSize; i++)
					TestData[i] = (BYTE)((i >> 8) + (i & 0xFF));   // Prepare data for writing

				if (!V2X_AES_encrypt(UserID, SoftwareEncryptionKeyIndex, TestData, TestSize, EncrData, &EncrDataSize))
				{
					errorflag = 1; LogError("Encryption failed !!!\n"); break;
				}

				else if (!V2X_AES_decrypt(UserID, SoftwareEncryptionKeyIndex, EncrData, EncrDataSize, PlainData, &PlainDataSize))
				{
					errorflag = 1; LogError("Decryption failed !!!\n"); break;
				}

				else if (memcmp(TestData, PlainData, TestSize) != 0)
				{
					errorflag = 1; LogError("Decrypted data incorrect !!!\n"); break;
				}

				if (checkKey() == ESC_KEY) break;  // Stop cycle if ESC key pressed

				LogScreen("Data size:%5d  Time:%5d ms\r", TestSize, (unsigned int)(Stat_Time_finish - Stat_Time_start));
			}
			LogScreen("\n");
		}
		else if (strncmp(cCommandBuffer, "randkeyfile", 10) == 0) {
			LogScreen("Create random encrypted key file using V2X Prototype random generator\n");
			LogScreen("------------------------------------------------------------\n");

			// Get file encryption password (command line or type in on keyboard)
			if (!Ask_Password(PASSWORD_PROMPT, UtilPassword)) break;

			memset(UserKey, 0, sizeof(UserKey));     // Clear keys array
			memset(UserKeySize, 0, sizeof(UserKeySize)); // Clear key size array
			memset(UserKeyID, 0, sizeof(UserKeyID));   // Clear keyID array

			if (iScanned == 0) { // No -kx arguments - generate one random key and save it to file
				if (!V2X_GetRandom(UserID, USER_KEY_SIZE, UserKey[0])) continue;
				HexDump("Generated key: ", UserKey[0], USER_KEY_SIZE);
				if (!Save_Key(UserKey[0], USER_KEY_SIZE, UserKeyID[0])) continue;
			}
			else { // Scan -kx arguments - generate random keys for each argument and save them to files, create init.txt script
				int cnt = 0;
				for (; cnt < iScanned; cnt++) {
					if (cCommandArg[cnt][0] != '-' || cCommandArg[cnt][1] != 'k' || cCommandArg[cnt][2]  < '0' || cCommandArg[cnt][2]  > '7') {
						LogError("ERROR: Wrong command line parameter %d, should be -k{0..7}\n", cnt);
						continue;
					}
					int keynum = cCommandArg[cnt][2] & 0x0F;
					UserKeySize[keynum] = USER_KEY_SIZE; // fix Key size - AES256
				}
				char tempstr[2000] = { 0x00 };
				sprintf(tempstr, "init -psw %s", UtilPassword);

				for (cnt = 0; cnt < MAX_USERS; cnt++) {
					if (UserKeySize[cnt]) {
						LogScreen("Generating random User %d key\n", cnt); //  generate and save to file the random key for each -kx option
						if (!V2X_GetRandom(UserID, USER_KEY_SIZE, (BYTE*)UserKey[cnt])) continue;
						HexDump("    ", UserKey[cnt], UserKeySize[cnt]);
						if (!Save_Key(UserKey[cnt], UserKeySize[cnt], UserKeyID[cnt])) continue;
						sprintf(tempstr + strlen(tempstr), " -k%d %02X%02X%02X%02X.key", cnt, UserKeyID[cnt][0], UserKeyID[cnt][1], UserKeyID[cnt][2], UserKeyID[cnt][3]);
					}
				}
				char cmdline[MAX_PATH + 1] = { "./init.txt" };
				if (!SaveToFile(cmdline, tempstr, strlen(tempstr) + 1))
					LogError("\nERROR: Command line file '%s' writing error\n\n", cmdline);
			}
		}
		else if (strcmp(cCommand, "init") == 0) {
			// optional: send a .txt file as content to be processed
			char cFilePath[MAX_PATH] = { 0x00 };
			if (strcmp(cCommandArg[0], "-f") == 0) {
				if (sscanf(cCommandArg[1], "%260s", cFilePath) == 1)
				{
					// read in file instead of single command line args
					int iSize = sizeof(cCommandBuffer);
					BYTE *  pucRet = LoadFromFile(cFilePath, cCommandBuffer, &iSize);
					if (pucRet == NULL) {
						LogError("ERROR: could not open file %s!\n", cFilePath);
						continue;
					}
//					for (i = 0; i < (int)strlen(cCommandBuffer); i++) cCommandBuffer[i] = toupper(cCommandBuffer[i]);
					goto fileinput;
				}
			}
			LogScreen("Initialize HSM: change Transport key, user keys/passwords\n");
			LogScreen("------------------------------------------------------------\n");

			memset(UserKey, 0, sizeof(UserKey));     // Clear keys array
			memset(UserKeySize, 0, sizeof(UserKeySize)); // Clear key size array
			memset(UserKeyID, 0, sizeof(UserKeyID));   // Clear keyID array

			// Load User keys from files on the host encrypted with utility password
			int cnt = 0;
			for (; cnt < iScanned; cnt++) {
				if (cCommandArg[cnt][0] != '-' || cCommandArg[cnt][1] != 'k' || cCommandArg[cnt][2]  < '0' || cCommandArg[cnt][2]  > '7') {
					LogError("ERROR: Wrong command line parameter %d, should be -k{0..7}\n", cnt);
					continue;
				}

				int keynum = cCommandArg[cnt][2] & 0x0F;

				if (UTIL_hexStrToArray(cCommandArg[++cnt], UserKeyID[keynum], KEYIDSIZE) == 0) {
					LogError("ERROR: Wrong command line parameter %d, should be 8 characters (4 bytes in HEX representation)\n", cnt);
					continue;
				}
				if (!V2X_LoadUserKey(UserKeyID[keynum], UtilPassword, UserKey[keynum], &UserKeySize[keynum])) continue;
			}

			if (!Initialize_HSM()) continue;  // Change HSM life cycle and Transport key
		}
		else if (strcmp(cCommand, "pwkeyfile") == 0) {
			LogScreen("Create encrypted key file using entered symbolic password\n");
			LogScreen("---------------------------------------------------------\n");

			// Get file encryption password (command line or type in on keyboard)
			if (!Ask_Password(PASSWORD_PROMPT, UtilPassword)) break;

			char EnteredKey[128] = { 0x00 };
			if (iScanned == 1 && strlen(cCommandArg[0]) <= 2*USER_KEY_SIZE) strcpy(EnteredKey, cCommandArg[0]);
			else if (!Ask_Password("Please enter password (8-32 characters): ", EnteredKey)) continue;

			Save_Key((BYTE*)EnteredKey, strlen(EnteredKey), UserKeyID[0]);
		}
		else if (strcmp(cCommand, "hexkeyfile") == 0) {
			LogScreen("Create encrypted key file using entered HEX key\n");
			LogScreen("--------------------------------------------------------\n");

			char HexKey[1025] = { 0x00 };
			if (iScanned == 1 && strlen(cCommandArg[0]) <= sizeof(HexKey) - 1)
				strcpy(HexKey, cCommandArg[0]);
			else {
				LogScreen("Please enter HEX key value (8-32 bytes): ");
				scanf("%1024s", HexKey);
			}
			BYTE BinaryKey[512] = { 0x00 };
			int BinaryKeySize = UTIL_hexStrToArray(HexKey, BinaryKey, sizeof(BinaryKey));
			if (BinaryKeySize < 8) { LogError("ERROR: Too short HEX value: %d bytes\n", BinaryKeySize); continue; }

			Save_Key(BinaryKey, BinaryKeySize, UserKeyID[0]);
		}
		else if (strcmp(cCommand, "sendcmd") == 0) {
			LogScreen("Send APDU command and receive response\n");
			LogScreen("----------------------------------------\n");

			char cCommandFrame[2 * MAX_APDU_SIZE] = { 0x00 };
			if (iScanned >= 1) {
				strcpy(cCommandFrame, cCommandArg[0]);
				if (iScanned > 1)
					LogScreen("\nIllegal arguments detected - will be ignored! \n");
			}
			else {
				LogScreen("Please enter APDU command: ");
				scanf("%3600s", cCommandFrame);
			}

			BYTE ucBinaryFrame[MAX_APDU_SIZE] = { 0x00 };
			int BinaryFrameSize = UTIL_hexStrToArray(cCommandFrame, ucBinaryFrame, sizeof(ucBinaryFrame));
			if ((BinaryFrameSize < 4) || (BinaryFrameSize > MAX_APDU_SIZE)) { LogError("ERROR: wrong command size\n");  continue; }

			int iRet = 0;
			Save_LogLevel = LogLevel;
			LogLevel = 3;

			memset(RESP_APDU, '\x00', sizeof(RESP_APDU));
			RESP_APDU_size = 0;
			// ???
			do
			{
				iRet = SPI_protocol_send(ucBinaryFrame, BinaryFrameSize, RESP_APDU, &RESP_APDU_size, MAX_APDU_TRIES, 1000);
				if (checkKey() == ESC_KEY) continue;  // Stop cycle if ESC key pressed
			} while (iRet != 1);

			LogLevel = Save_LogLevel;
			//LogScreen("\n=========================================================\n");
		}
		else if (strcmp(cCommand, "setac") == 0) {
			LogScreen("Change / Set Access Condition Byte\n");
			LogScreen("------------------------------------------------------------\n");

			/*
			get:
			mode:   0x00 - get files access conditions array
			        0x01 - get keys access conditions array
	                0x02 - get V2X Prototype life cycle access conditions array
			set:
					fileID (0, 0xE000 ... 0xE009)
					keyID (0xF000...0xF007)
					Lifecycle AC (0xFFFF)
			*/

			if (iScanned != 3 ) {
				LogScreen("Please use the correct format (3 values required): type of AC [userX, fileX or lifecycle], byte to change [byteX], value where x ... [0 ... 7]");
				continue;
			}

			BYTE ucMode = 0;
			BYTE ucIndex = 0;
			BYTE ucByteNumber = 0x00;
			BYTE ucValue = 0x00;

			if (strcmp(cCommandArg[0], "lifecycle") == 0) {
				ucMode = 0x02;
			}
			else if (strncmp(cCommandArg[0], "user", 4) == 0)
			{
				ucMode = 0x01;
				if (sscanf(cCommandArg[0], "user%hhx", &ucIndex) != 1)
					continue;

				// allowed range: 1 ... 8 AC_Keys[MAX_USERS], MAX_USERS 8
				if ((ucIndex < 1) || (ucIndex > 8)) {
					LogScreen("Illegal value of parameter userX; allowed: userX, whereas X is in the range [1 ... 8] \n");
					continue;
				}
				// decrement for 0 based index
				ucIndex--;
			}
			else if (strncmp(cCommandArg[0], "file", 4) == 0)
			{
				ucMode = 0x00;
				if (sscanf(cCommandArg[0], "file%hhx", &ucIndex) != 1)
					continue;

				// allowed range: 1 ... 11 [AC_Files[1+MAX_NVM_FILES], MAX_NVM_FILES 10
				if ((ucIndex < 1) || (ucIndex > 11)) {
					LogScreen("Illegal value of prameter fileX; allowed: fileX, whereas X is in the range [1 ... 11] \n");
					continue;
				}
				// decrement for 0 based index
				ucIndex--;
			}
			else {
				LogScreen("Illegal value of prameter 1; allowed: userX, fileX or lifecycle \n");
				continue;
			}

			if (sscanf(cCommandArg[1], "byte%hhx", &ucByteNumber) != 1) {
				LogScreen("Illegal value of prameter 2; allowed: byteX \n");
				continue;
			}

			if (sscanf(cCommandArg[2], "%hhx", &ucValue) != 1) {
				LogScreen("Illegal value of prameter 3; allowed: single byte \n");
				continue;
			}

			LogScreen("Authenticate user 0 and start secure session\n");
			UserID = 0;
			// Authenticate
			if (!GetUserKey(UserID)) { errorflag = 1; break; }
			if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) break;
			BYTE ucACs[128] = { 0x00 };
			V2X_get_access_conditions(UserID, ucMode, ucACs );
			ucACs[ucByteNumber + (ucIndex * AC_SIZE)] = ucValue;
			LogScreen("Change V2X keys AC - User 0 auth required\n");

			unsigned short sIndex = 0x0000;
			switch (ucMode)
			{
			case 0x02:
				// Lifecycle
				sIndex = NVM_OFFSET_LIFECYCLE;
				break;
			case 0x01:
				// User
				sIndex = (NVM_OFFSET_PASSWORDS + ucIndex);
				break;
			case 0x00:
				// File
				sIndex = (NVM_OFFSET_FILES + ucIndex);
				break;
			default:
				errorflag = 1; break;
			};

			if (V2X_change_access_conditions(UserID, sIndex, &(ucACs[(ucIndex * AC_SIZE)]), AC_SIZE) == 0) break;
			V2X_Close(UserID); // Close Admin session with HSM

		}
		else if (strcmp(cCommand, "returnfl") == 0) {
			LogScreen("Return to flash loader - FOR IFX INTERNAL USE ONLY! \n");
			LogScreen("------------------------------------------------------------\n");

			if (iScanned > 0)
				LogScreen("\nIllegal arguments detected - will be ignored! \n");

			LogScreen("\nAre you sure you want to reactivate the FlashLoader [Y/N] ?  ");
			keypressed = getKey();
			LogScreen("\n");

			if (toupper(keypressed) != 'Y') continue;

			LogScreen("Authenticate with Transport key and start secure session\n");

			UserID = 0; // Transport Key
			if (!GetUserKey(UserID)) { errorflag = 1; return 0; }
			if (V2X_Open(UserID, UserKey[UserID], UserKeySize[UserID]) == 0) break;
			SessionActive[0] = 0;
			{
				BYTE ReactivateFlashLoaderAPDU[] = { 0xC2, 0xA0, 0x00, 0x00, 0x10 };
				if (!V2X_send_apdu(UserID, ReactivateFlashLoaderAPDU, sizeof(ReactivateFlashLoaderAPDU), RESP_APDU, &RESP_APDU_size, 1000)) break;
			}
			HexDump("Response: ", RESP_APDU, 2);
			//if (CheckResponseNoData(ret, "Reactivate FlashLoader", 0))
		    LogScreen("FlashLoader reactivated OK.\n");
			//else LogError("\nERROR: FlashLoader reactivation failed !!!\n");
			break;
		}
		else if (strcmp(cCommand, "writefile") == 0) {
			if (iScanned != 2) {
				LogScreen("Please use the correct format (2 values required): file index, data to be written \n");
				continue;
			}

			int FileID = 0;
			if (strlen(cCommandArg[0]) != 0) {
				FileID = atoi((const char*)&(cCommandArg[0]));
			}

			BYTE ucData[MAX_DATA_SIZE] = { 0x00 };
			int iDataLen;
			if((strcmp(cCommandArg[1], "0") == 0) || (strcmp(cCommandArg[1], "NULL") == 0))
			{
				// nothing to do
				iDataLen = sizeof(ucData);
				LogScreen("Erase File \n");

			}
			else
			{
				iDataLen = UTIL_hexStrToArray(cCommandArg[1], ucData, sizeof(ucData));
				if (iDataLen == 0) {
					LogScreen("Illegal value of prameter 2; max allowed: 1800 byte \n");
					continue;
				}
				LogScreen("Write Data to File \n");
			}
			LogScreen("------------------------------------------------------------\n");

			UserID = 1;
			if (!GetUserKey(UserID)) { errorflag = 1; return 0; }

			if (V2X_Open(UserID, UserKey[UserID], strlen(UserKey[UserID])) == 0) break;

			if (!V2X_write_file(UserID, FileID, ucData, iDataLen)) break;

		}
		else if (strcmp(cCommand, "readfile") == 0) {
			if (iScanned != 1) {
				LogScreen("Please use the correct format (1 value required): file index\n");
				continue;
			}
			LogScreen("Read file content\n");
			LogScreen("------------------------------------------------------------\n");

			int FileID = 0;
			if (strlen(cCommandArg[0]) != 0) {
				FileID = atoi((const char*)&(cCommandArg[0]));
			}

			UserID = 1;
			if (!GetUserKey(UserID)) { errorflag = 1; return 0; }

			if (V2X_Open(UserID, UserKey[UserID], strlen(UserKey[UserID])) == 0) break;

			BYTE ucData[MAX_DATA_SIZE] = { 0x00 };
			int iDataLen = sizeof(ucData);
			if (!V2X_read_file(UserID, FileID, ucData, &iDataLen)) break;

			HexDump("File content: ", ucData, iDataLen);
			LogScreen("\n============================================================\n");
		}
		else if (strcmp(cCommand, "importkey") == 0) {

			if (iScanned != 2) {
				LogScreen("Please use the correct format (2 values required): key index, key data to be imported \n");
				continue;
			}

			LogScreen("Import Private Key\n");
			LogScreen("------------------------------------------------------------\n");

			// First argument (optional): KeyIndex
			if (strlen(cCommandArg[0]) != 0) {
				KeyIndex = atoi((const char*)&(cCommandArg[0]));
			}
			else {
				KeyIndex = 0;
			}
			BYTE BYTE_PrivKeyImport[ECC_PRIV_KEY_SIZE];
			int iPrivKeyLen = UTIL_hexStrToArray(cCommandArg[1], BYTE_PrivKeyImport, sizeof(BYTE_PrivKeyImport));
			if (iPrivKeyLen == 0) {
				LogScreen("Illegal value of prameter 2; max allowed: 32 byte \n");
				continue;
			}

			UserID = 1;
			if (!GetUserKey(UserID)) { errorflag = 1; return 0; }

			if (V2X_Open(UserID, UserKey[UserID], strlen(UserKey[UserID])) == 0) break;

			ECPrivateKey ECPrivKeyImport = { ECC_PRIV_KEY_SIZE, BYTE_PrivKeyImport };

			if (V2X_import_private_key(UserID, AlgID, KeyIndex, &ECPrivKeyImport) == 0) {
				Log("\nError importing private key!\n");
			}
			// reconstruct public key
			if (!V2X_ecqv_reception(UserID, AlgID,
				KeyIndex,
				KeyIndex,
				NULL, 0,
				NULL, 0,
				NULL, 0,
				&ECPublicKeyChip)) {
				errorflag = 1; return 0;
			}

			if (V2X_import_public_key(UserID, AlgID, KeyIndex, &ECPublicKeyChip) == 0) {
				Log("\nError importing public key!\n");
			}

			LogScreen("Key %d imported successfully\n", KeyIndex);
		}
		else if (strcmp(cCommand, "updatefw") == 0) {
			if (iScanned != 1) {
				LogScreen("Please use the correct format (1 value required): firmware file (*.bin)\n");
				continue;
			}
			LogScreen("Update firmware ...\n");
			LogScreen("------------------------------------------------------------\n");

			if (Program_HSM_Firmware(cCommandArg[0]) == 0) {
				Log("\nError updating firmware!\n");
			}
		}
		else {
			LogScreen("Unknown or unsupported command %s!\n", cCommand);
		}

	} while (1);

err_exit:
	V2X_Close(UserID); // Close session with V2X Prototype
	V2X_Shutdown(); // Turn off the SPI host adapter's power pins and close the SPI host adapter

	return 0;
}

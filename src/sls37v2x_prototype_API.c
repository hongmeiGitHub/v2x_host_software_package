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

#include "sls37v2x_prototype_API.h"

/*******************************
*    Variable Definitions      *
*******************************/


// Configuration of ECIES encrypt command:
//--------------------------------------------
// ECIES_GenerateEphemeralKey (P1 P2 parameters of APDU) can have the following values:
//  P1P2=0000 means that ephemeral keys is generated during ECIES encrypt (default)
//  P1P2=8000 means that previously imported (temporary import with key index 0 - stored in V2X RAM) public and private keys are used as ephemeral keys
//  P1P2=8xxx (xxx = key index) means that key pair stored in V2X Prototype NVM is used as ephemeral
UINT16 ECIES_GenerateEphemeralKey = 0x0000;

int V2X_FirmwareVersion = 0;

static BYTE APDUbuffer[MAX_APDU_SIZE];
static int APDUsize;

static BYTE RESP_APDU[MAX_APDU_SIZE];
static int  RESP_APDU_size;

static BYTE SessionKey[MAX_USERS][SESSION_KEY_SIZE*2];
int SessionActive[MAX_USERS];
int SessionID[MAX_USERS];

BYTE ZeroID[] = {0x00, 0x00, 0x00, 0x00}; // Zero key identifier returned by V2X Prototype if key is not set

uint16_t SW1SW2;
int errorflag;


/*******************************
*    Function Definitions      *
*******************************/

//-----------------------------------------------------------------------------
// Initialize SPI interface, Power On
// Parameters:
//  Input:	none
//  Output:	none
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_Initialize()
{
    int ret, i, bitrate = SPI_BITRATE;
    FILE *stream;
    char text[200];

    memset(SessionActive, 0, sizeof(SessionActive));
    memset(SessionID, 0, sizeof(SessionID));
    memset(SessionKey, 0, sizeof(SessionKey));

	// Check if configuration file exists, try getting SPI bitrate and debug mode from it
    if (FileExists(CONFIG_FILENAME))
        if ((stream = openFile(CONFIG_FILENAME)) != NULL) {
            // First line encodes SPI bit tate in kHz (decimal number)
            // ex., 500 = 500 kHz, 1000 = 1 MHz, 8000 = 8 MHz
            if (readLineFromFile(stream, text, sizeof(text)-1)) {
                if ((i = atoi(text)) > 0) bitrate = i;
            // 2nd line encodes Console screen Debug print level
            // 0 - no screen log
            // 1 - minimum screen log
            // 2 - APDUs and responses shown on screen
            // 3 - deep SPI protocol debugging, all debug messages shown on screen
                if (readLineFromFile(stream, text, sizeof(text)-1)) {
                    if ((i = atoi(text)) > 0) LogLevel = i;
            // 3rd line encodes log file Debug print level (encoding same as console screen)
                    if (readLineFromFile(stream, text, sizeof(text)-1)) {
                        if ((i = atoi(text)) > 0) LogLevelFile = i;
                    }
                }
            }
            closeFile(stream);
        }
    // Find SPI host adapter, open it and configure SPI host adapter
    ret = SPI_protocol_init(bitrate);

    // Turn on the SPI host adapter's power pins.
    SPI_power_on();

    return ret;
}
//-----------------------------------------------------------------------------
// Close SPI connection to V2X Prototype. Power off V2X Prototype if available on current platform.
// Parameters:
//  Input:	none
//  Output:	none
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_Shutdown()
{
    SPI_power_off(); // Turn off the SPI host adapter's power pins.
    SPI_protocol_close();    // Close the SPI host adapter

    return 1;
}
//-----------------------------------------------------------------------------
int CheckResponse(int ret, char *funcname, int index)
{
    if (!ret) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) APDU failed !!!\n", funcname, index);
#endif
        errorflag=1;
        return 0;
    }
    else if (RESP_APDU_size < 2) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) failed !!! Response len=%d\n", funcname, index, RESP_APDU_size);
#endif
        errorflag=1;
        return 0;
    }
    else if (RESP_APDU[RESP_APDU_size-2] != 0x90 || RESP_APDU[RESP_APDU_size-1] != 0x00) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) failed !!! SW1SW2=%02X%02X\n", funcname, index, RESP_APDU[RESP_APDU_size-2], RESP_APDU[RESP_APDU_size-1]);
#endif
        errorflag=1;
        return 0;
    }
    RESP_APDU_size -= 2;
    return 1;
}
//-----------------------------------------------------------------------------
int CheckResponseIgnoreData(int ret, char *funcname, int index)
{
    if (!ret) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) APDU failed !!!\n", funcname, index);
#endif
        errorflag=1;
        return 0;
    }
    RESP_APDU_size -= 2;
    return 1;
}
//-----------------------------------------------------------------------------
int CheckResponseNoData(int ret, char *funcname, int index)
{
    if (!ret) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) APDU failed !!!\n", funcname, index);
#endif
        errorflag=1;
        return 0;
    }
    else if (RESP_APDU_size < 2) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) failed !!! Response len=%d\n", funcname, index, RESP_APDU_size);
#endif
        errorflag=1;
        return 0;
    }
    else if (RESP_APDU[RESP_APDU_size-2] != 0x90 || RESP_APDU[RESP_APDU_size-1] != 0x00) {
#ifdef DEBUG
        LogError("ERROR: %s (index=%04X) failed !!! SW1SW2=%02X%02X\n", funcname, index, RESP_APDU[RESP_APDU_size-2], RESP_APDU[RESP_APDU_size-1]);
#endif
        errorflag=1;
        return 0;
    }
    return V2X_SUCCESS;
}
//-----------------------------------------------------------------------------
BYTE ConvertAlgID(BYTE alg)
{
    switch (alg) {
        case ECDSA_NISTP256_WITH_SHA256     : return 0;
        case ECIES_NISTP256                 : return 0;
        case ECDSA_BRAINPOOLP256_WITH_SHA256: return 1;
        case ECIES_BRAINPOOLP256            : return 1;
        case ECDSA_NISTP384_WITH_SHA256     : return 2;
        case ECIES_NISTP384                 : return 2;
        case ECDSA_BRAINPOOLP384_WITH_SHA256: return 3;
        case ECIES_BRAINPOOLP384            : return 3;
    }
	return 0;
}
//-----------------------------------------------------------------------------
void ShortOrExtendedLength(const BYTE *data, int datasize)
{
    if (datasize == 0) {
        APDUbuffer[4] = (BYTE)(datasize);                // Le
        APDUsize = 5;
    }
    else if (datasize < 256) {
        APDUbuffer[4] = (BYTE)(datasize);               // Lc
        memcpy(APDUbuffer+5, data, datasize);           // Data
        APDUbuffer[5+datasize] = 0x00;                  // Le
        APDUsize = 6 + datasize;
    }
    else {
        APDUbuffer[4] = 0;
        APDUbuffer[5] = (BYTE)((datasize) >> 8) & 0xFF;  // Lc extended
        APDUbuffer[6] = (BYTE)((datasize) & 0xFF);
        memcpy(APDUbuffer+7, data, datasize);            // Data
        APDUbuffer[7+datasize] = 0x00;                   // Le
        APDUsize = 8 + datasize;
    }
}

//=========================================================================
// Send plain text or secure messaging APDU
//  Input: - Plain command APDU (array reserved must be long enough to add 16 bytes MAC)
//         - APDU length length in bytes
//         - pointer to a byte array reserved for the response
//         - pointer to int reserved for the response length
//         - response timeout value
// Returns 1 in case of success or 0 in case of packet transmission failure
//=========================================================================
int V2X_send_apdu( int	    userid,     // In: Admin/User ID
                   BYTE    *apdudata,   // APDU
                   int      apdulen,    // APDU length
                   BYTE    *response,   // Array reserved for response
                   int     *respsize,   // Response size
                   int      timeout)    // response timeout
{
    int ret, encrlen, datalen, pi, padlen, dataofs, indataofs;
    BYTE MAC[MAC_SIZE+16];
    BYTE apdu[MAX_APDU_SIZE];

    if (apdulen == 0 || apdulen > MAX_APDU_SIZE)
        {LogError("ERROR: V2X_send_apdu: Wrong APDU size: %d\n", apdulen); return 0; }
    SW1SW2 = 0;
    RESP_APDU_size = 0;
	memset(RESP_APDU, '\x00', sizeof(RESP_APDU));
    if (SessionActive[userid] == 0) {
        ret = SPI_protocol_send(apdudata, apdulen, RESP_APDU, &RESP_APDU_size, MAX_APDU_TRIES, timeout);

        if (RESP_APDU_size >= 2) SW1SW2 = (UINT16)((RESP_APDU[RESP_APDU_size-2] << 8) + RESP_APDU[RESP_APDU_size-1]);
        if (response) memmove(response, RESP_APDU, RESP_APDU_size);
        if (respsize) *respsize = RESP_APDU_size;
        goto apdu_success_exit;
    }
#ifdef DEBUG
    if (LogLevel > 1 || LogLevelFile > 1) HexDumpPort("SM>>: ", apdudata, apdulen);
#endif
    // Modify CLA for SM -  clear bits 7,3,2,1,0 and set SM bits 6,5,4
    apdu[0] = (apdudata[0] & 0x0F) | (SessionID[userid] << 4);

    // Check incoming APDU format
    if (apdudata[4] == 0x00 && apdulen > 7) { // Extended Lc
        indataofs = 7;
        datalen = (apdudata[5] << 8) + apdudata[6];
    }
    else {                                // Short Lc
        indataofs = 5;
        datalen = (BYTE)apdudata[4];
    }
    if (apdulen < 5) goto apdu_error_exit; // APDU too short
    if (apdulen > 5 && apdulen != indataofs + datalen + 1                   // Check short APDU format, Le present
                    && apdulen != indataofs + datalen + 2                   // Check extended APDU format, Le present
                    && apdulen != indataofs + datalen) goto apdu_error_exit;// Check APDU format, Le absent
    if (indataofs + datalen + 2*MAC_SIZE >= MAX_APDU_SIZE) goto apdu_error_exit; // Data too long

    // APDU format may change from short to extended if Lc with SM MAC and padding exceeds 255:
    if (apdulen > 224) dataofs = 7; // Extended Lc
    else               dataofs = 5; // Short Lc

    memmove(apdu+1, apdudata+1, 3); // Copy INS, P1, P2

    // Modify Lc if addition of padding and MAC changes length from short to extended
    if (dataofs == 7) {
        apdu[4] = 0x00;
        apdu[5] = (BYTE)((datalen >> 8) & 0xFF);
        apdu[6] = (BYTE) (datalen & 0xFF);
    }
    else if (indataofs == 5) apdu[4] = apdudata[4];  // Copy Le for short length

    if (datalen != 0) memmove(apdu+dataofs, apdudata+indataofs, datalen); // Copy data

    Crypto_MAC( SessionKey[userid]+SESSION_KEY_SIZE, // Use last 32 bytes of session key to MAC encrypted data
                    SESSION_KEY_SIZE,// 32 bytes
                    SESSION_ENC_ALG, // AES256
                    SESSION_ENC_MODE,// CBC mode
                    apdu,            // Input data (MAC over encrypted data)
                    dataofs+datalen, // size of input data
                    MAC);            // return MAC here
    pi = 0;
    if (datalen != 0) {
        pi = 1;
        memmove(apdu+dataofs+1, apdu+dataofs, datalen); // Insert one byte
        if (datalen % 16 != 0) { // Padding needed or not ?
            datalen = ISO_padding_16(apdu + dataofs + pi, datalen);
            apdu[dataofs] = 0x01; // Insert Padding indicator
        }
        else apdu[dataofs] = 0x00; // No-padding indicator

        Crypto_Encrypt(SessionKey[userid],   // Use 1st 32 bytes of key (ENC) to Encrypt data
                        SESSION_KEY_SIZE,// 32 bytes
                        SESSION_ENC_ALG, // AES256
                        SESSION_ENC_MODE,// CBC mode
                        apdu+dataofs+pi, // Plain data
                        datalen,         // size of padded data
                        apdu+dataofs+pi, // Encrypted data will be returned here
                        &encrlen);       // size of encrypted data will be returned here
    }
    else {
        encrlen = 0;
        apdu[dataofs] = 0x00; // No-padding indicator
    }
    // Modify Lc for SM
    if (dataofs == 7) {       // Extended Lc
        apdu[5] = (BYTE)(((encrlen+MAC_SIZE+pi) >> 8) & 0xFF);
        apdu[6] = (BYTE) ((encrlen+MAC_SIZE+pi) & 0xFF);
    }
    else {                    // Short Lc
        apdu[4] = (BYTE) ((encrlen+MAC_SIZE+pi) & 0xFF);
    }

    // Copy MAC
    memmove(apdu+dataofs+pi+encrlen, MAC, MAC_SIZE);

    // Insert 16 bytes for MAC - move Le
    apdu[dataofs+pi+encrlen+MAC_SIZE] = apdudata[apdulen-1];

    ret = SPI_protocol_send(apdu, dataofs+pi+encrlen+MAC_SIZE+1, RESP_APDU, &RESP_APDU_size, MAX_APDU_TRIES, timeout);

    if (RESP_APDU_size < 1 + 16 + MAC_SIZE + 2) { // PI + data + MAC + SW1SW2
        if (response) memmove(response, RESP_APDU, RESP_APDU_size);
        goto apdu_success_exit; // Return as plain text response
    }
    RESP_APDU_size -= 1+MAC_SIZE+2;

    Crypto_Decrypt(SessionKey[userid],   // Use 1st 32 bytes of key (ENC) to Decrypt data
                    SESSION_KEY_SIZE,// 32 bytes
                    SESSION_ENC_ALG, // AES256
                    SESSION_ENC_MODE,// CBC mode
                    RESP_APDU+1,     // Encrypted data
                    RESP_APDU_size,  // size of Encrypted data
                    RESP_APDU+1,     // Plain data will be returned here
                    &encrlen);       // size of decrypted data will be returned here

    Crypto_MAC(SessionKey[userid]+SESSION_KEY_SIZE, // Use last 32 bytes of session key to MAC encrypted data
                    SESSION_KEY_SIZE,// 32 bytes
                    SESSION_ENC_ALG, // AES256
                    SESSION_ENC_MODE,// CBC mode
                    RESP_APDU+1,     // Input data (MAC over encrypted data)
                    RESP_APDU_size,  // size of input data
                    MAC);            // return MAC here

    if (memcmp(MAC, 1+RESP_APDU+RESP_APDU_size, MAC_SIZE) != 0) { // If MAC is wrong:
        //if (respsize) *respsize = RESP_APDU_size+2;  // Remove MAC, leave: data + SW1SW2
        //memmove(RESP_APDU+RESP_APDU_size, RESP_APDU+RESP_APDU_size+MAC_SIZE, 2); // Move SW1SW2 bytes
        if (respsize) *respsize = 0;
        return 0;                    // Return SM Error
    }
    if (RESP_APDU[0] == 0x01)
        padlen = Remove_ISO_padding(RESP_APDU+1, RESP_APDU_size); // Remove ISO padding
    else padlen = RESP_APDU_size;

    memmove(RESP_APDU, 1+RESP_APDU, padlen); // Remove PI
    memmove(RESP_APDU+padlen, 1+RESP_APDU+RESP_APDU_size+MAC_SIZE, 2); // Move SW1SW2 bytes
    padlen += 2;
    RESP_APDU_size = padlen;
#ifdef DEBUG
    if (LogLevel > 1 || LogLevelFile > 1) HexDumpPort("SM<<: ", RESP_APDU, RESP_APDU_size);
#endif
    if (response) memmove(response, RESP_APDU, RESP_APDU_size);

apdu_success_exit:
    if (respsize) *respsize = RESP_APDU_size;
    if (RESP_APDU_size >= 2) SW1SW2 = (UINT16)((RESP_APDU[RESP_APDU_size-2] << 8) + RESP_APDU[RESP_APDU_size-1]);
    return ret;

apdu_error_exit:
#ifdef DEBUG
        LogError("ERROR: V2X_send_apdu: APDU format error\n");
        HexDump("", apdudata, apdulen);
#endif
    return 0;
}

//-----------------------------------------------------------------------------
// Send AUTHENTICATE command to V2X Prototype
// Parameters:
//  Input:	keyind : 0 or 0xF000 - Transport key
//                   1 or 0xF001 - Admin
//                   2 ... 7 or 0xF002 ... 0xF007 - Users 2 ... 7
//          authentication data         NULL - reset current secure session
//          authentication data length  0 - reset current secure session
//  Output:	none
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_Authenticate(
	int	            userid,     // In: Admin/User ID
    uint8_t        *authdata,	// In: pointer to authentication data array
    size_t          authlen)    // In: The length of the authentication data array
{
    int ret;
    // Build AUTHENTICATE APDU
    BUILD_APDU_START(0x82)
    BUILD_APDU_INDEX(userid)
    ShortOrExtendedLength(authdata, authlen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    if (authdata == NULL || authlen == 0) return 1; // Don't check error when closing secure session
    if (!CheckResponseNoData(ret, "V2X_Authenticate", userid)) return 0;
    return V2X_SUCCESS;
}
//-----------------------------------------------------------------------------
// Authenticates to V2X Prototype and creates secure session
// Parameters:
//  Input:	UserID : 0 or 0xF000 - Transport key
//                   1 or 0xF001 - Admin
//                   2 ... 7 or 0xF002 ... 0xF007 - Users 2 ... 7
//          password/key(up to 32 bytes) - NULL - no authentication
//          password/key length          - 0 - no authentication
//  Output:	none
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_Open(
	int	            userid,         // In: Admin/User ID
    uint8_t        *password_key,	// In: pointer to Admin/User password/key byte array
    size_t          passwordLen)    // In: The length of the password_key in bytes
{
    int ret;
    BYTE GetRandomAPDU[] = {0x80, 0x84, 0x00, 0x00, RANDOM_SIZE };
    BYTE buffer[RANDOM_SIZE+16];
    BYTE mac[64];
    int maclen;

    SessionActive[userid] = 0;
    if (password_key == NULL || passwordLen == 0) return 1; // No authentication/session

    if (userid < 0 || userid >= MAX_USERS) {
#ifdef DEBUG
        LogError("ERROR: V2X_Open: UserID %d exceeds max. users %d\n", userid, MAX_USERS);
#endif
        return 0;
    }

    ret = V2X_send_apdu(userid, GetRandomAPDU, sizeof(GetRandomAPDU), RESP_APDU, &RESP_APDU_size, 200);
    if (!CheckResponse(ret, "V2X_GetRandom", 0)) {
        return 0;
    }
    buffer[0] = (BYTE)((userid >> 8)  & 0xFF);
    buffer[1] = (BYTE)(userid & 0xFF);
    memcpy(buffer+2, RESP_APDU, RANDOM_SIZE);

    // Use HMAC to calculate challenge response
    maclen = Crypto_MAC(password_key, passwordLen, // Secret: Password
						 ALG_HMAC, 0,				// Mode HMAC
                         buffer, 2+RANDOM_SIZE,     // Data: User ID || Random
                         mac);                      // MAC will be placed here

    if (ret = V2X_Authenticate(userid, mac, RANDOM_SIZE)) {
        // Use KDF2 to derive session keys
        Crypto_KDF(password_key, passwordLen,// Secret: Password
                          buffer+2, RANDOM_SIZE,    // Derivation parameter KDP: random
                          SESSION_KEY_SIZE,         // KDF2 generates 2x 32-bytes keys (ENC, MAC)
                          SessionKey[userid]);
        SessionActive[userid] = 1;
        SessionID[userid] = userid;
    }
    return ret;
}
//-----------------------------------------------------------------------------
// Close secure session with V2X Prototype
// Parameters:
//  Input:	none
//  Output:	none
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_Close(int userid) // In: Admin/User ID
{
    if (SessionActive[userid])
        V2X_Authenticate(SessionID[userid], NULL, 0); // Reset secure session
    SessionActive[userid] = 0;
	memset(SessionKey[userid], '\x00', sizeof(SessionKey[userid]));
    return V2X_SUCCESS;
}
//-----------------------------------------------------------------------------
// Send Get Firmware version APDU
// Parameters:
//  Input:	pointer to a buffer for firmware version string
//  Output: zero terminated V2X Prototype firmware version string copied to the array
//  Return: 0 in case of error or numeric firmware version (ex., 205 - ver.2.0.5)
//-----------------------------------------------------------------------------
int V2X_firmware_version(int    userid,     // In: Admin/User ID
                         char   *buffer) // Out: array reserved for firmware version
{
    int ret;
    BYTE GetVersionAPDU[] = {0x80, 0xCA, 0x00, 0x00, 0x00 };

    ret = V2X_send_apdu(userid, GetVersionAPDU, sizeof(GetVersionAPDU), RESP_APDU, &RESP_APDU_size, 50);
 //   if (!CheckResponse(ret, "V2X_firmware_version", 0)) ret = 0;
 //   else {
 //       RESP_APDU[RESP_APDU_size++] = 0;
 //       if (buffer) memcpy(buffer, RESP_APDU, RESP_APDU_size);

 //   ret = 1;
 //   if (RESP_APDU_size >= 30 &&
 //       isdigit(RESP_APDU[25]) &&
 //       isdigit(RESP_APDU[27]) &&
 //       isdigit(RESP_APDU[29]))
 //           ret = (RESP_APDU[25] & 0x0F) * 100 +
 //                 (RESP_APDU[27] & 0x0F) * 10 +
 //                 (RESP_APDU[29] & 0x0F);
 //   }

 //   if(!strncmp(RESP_APDU, "Infineon SLS37 V2X Prototype v1.0", 33)) ret = 300; //Added support for new naming
//	  if(!strncmp(RESP_APDU, "Infineon SLS37 V2X Prototype v1.1", 33)) ret = 300; //Added support for new naming

	ret = V2X_send_apdu(userid, GetVersionAPDU, sizeof(GetVersionAPDU), RESP_APDU, &RESP_APDU_size, 50);
	if (!CheckResponse(ret, "HSM_firmware_version", 0)) ret = 0;
	else {
		RESP_APDU[RESP_APDU_size++] = 0;
		if (buffer) memcpy(buffer, RESP_APDU, RESP_APDU_size);

		ret = 0;

		if (!strncmp(RESP_APDU, "Infineon SLI97 V2X HSM v.", 25)) { //Old naming convention, e.g. 2.0.7 -> 207
			if (RESP_APDU_size >= 30 &&
				isdigit(RESP_APDU[25]) &&
				isdigit(RESP_APDU[27]) &&
				isdigit(RESP_APDU[29]))
				ret = (RESP_APDU[25] & 0x0F) * 100 +
				(RESP_APDU[27] & 0x0F) * 10 +
				(RESP_APDU[29] & 0x0F);
			else LogError("Version String '%s' was not recognized\n", RESP_APDU);
		}
		else if (!strncmp(RESP_APDU, "Infineon SLS37 V2X Prototype v", 30)) { //New naming convention, e.g. 1.$
			if (RESP_APDU_size >= 33 &&
				isdigit(RESP_APDU[30]) &&
				isdigit(RESP_APDU[32]))
				ret = (RESP_APDU[30] & 0x0F) * 100 + 200 +
				(RESP_APDU[32] & 0x0F);
			else LogError("Version String '%s' was not recognized\n", RESP_APDU);
		} 
		else if (!strncmp(RESP_APDU, "Infineon SLS37 V2X SPI Flashloader v.", 37)) { //Flash loader version st$
			if (RESP_APDU_size >= 42 &&
			isdigit(RESP_APDU[37]) &&
			isdigit(RESP_APDU[39]) &&
			isdigit(RESP_APDU[41]))
			ret = (RESP_APDU[37] & 0x0F) * 100 + 100 +
			(RESP_APDU[39] & 0x0F) * 10 +
			(RESP_APDU[41] & 0x0F);
			else LogError("Version String '%s' was not recognized\n", RESP_APDU);
		}
		else { //unknown version string
			LogError("Version String '%s' was not recognized\n", RESP_APDU);
		}
	}

    return ret;
}
//-----------------------------------------------------------------------------
// Send GetChipID APDU - returns V2X Prototype chip unique identifier (serial number - 12 bytes)
// Parameters:
//  Input:	pointer to a buffer for ChipID
//  Output: V2X Prototype unique ID copied to the array
//-----------------------------------------------------------------------------
V2X_RESULT V2X_GetChipInfo(int	   userid,     // In: Admin/User ID
                           char   *buffer)     // Out: array reserved for Chip data
{
    int ret;
    BYTE GetChipIDAPDU[] = {0x80, 0xCA, 0x00, 0x01, 0x00 };

    ret = V2X_send_apdu(userid, GetChipIDAPDU, sizeof(GetChipIDAPDU), RESP_APDU, &RESP_APDU_size, 50);
    if (!CheckResponse(ret, "V2X_GetChipInfo", 0)) ret = 0;
    else {
        if (buffer) memcpy(buffer, RESP_APDU, RESP_APDU_size);
    }
    return ret;
}
//-----------------------------------------------------------------------------
// Send GetKeyID APDU - returns V2X Prototype key identifiers of a Transport, Admin or User2..7 - 4 bytes each)
// Parameters:
//  Input:	pointers to a buffer for KeyID
//  Output: V2X Prototype key identifiers copied to these 3 arrays
//-----------------------------------------------------------------------------
V2X_RESULT V2X_GetKeyID(int	   userid,          // In: Admin/User ID (used to authenticate and create secure session)
                        BYTE   keynr,           // In: Key number - the key identifier of key stored in V2X Prototype will be returned
                        BYTE   *keyID)          // Out: array reserved for KeyID (4 bytes)
{
    int ret;
    BYTE GetKeyIDAPDU[] = {0x80, 0xCA, keynr, 0x04, 0x00 };


    ret = V2X_send_apdu(userid, GetKeyIDAPDU, sizeof(GetKeyIDAPDU), RESP_APDU, &RESP_APDU_size, 50);
    if (!CheckResponse(ret, "V2X_GetKeyID", 0)) ret = 0;
    else {
        if (keyID) memcpy(keyID, RESP_APDU, KEYIDSIZE);
    }

    return ret;
}
//-----------------------------------------------------------------------------
// Get number of total private key slots in NVM
// Parameters:
//  Input:	none
//  Returns integer - number of total private key slots in NVM
//-----------------------------------------------------------------------------
V2X_RESULT V2X_GetMemoryInfo(int userid) // In: Admin/User ID
{
    int ret;
    BYTE GetMemoryAPDU[] = {0x80, 0xCA, 0x00, 0x06, 0x00 };


    ret = V2X_send_apdu(userid, GetMemoryAPDU, sizeof(GetMemoryAPDU), RESP_APDU, &RESP_APDU_size, 50);
    if (!CheckResponse(ret, "V2X_GetMemoryInfo", 0)) ret = 0;
    else {
        if (RESP_APDU_size != 2) ret = 0;
        else ret = (int)(RESP_APDU[0]*256 + RESP_APDU[1]);
    }

    return ret;
}
//-----------------------------------------------------------------------------
// Deletes a single or all private keys stored in V2X Prototype.
// Can be used in a specific key revocation or FIPS zeroization.
// Parameters:
//  Input:	index of a private key to delete. Zero means delete all private keys.
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_DeletePrivateKey(
    int         userid, // In: Admin/User ID
    uint32_t    index)  // In:  index of a private key to delete (1...3000). Zero - delete all private keys
{
    int ret, timeout;

    BUILD_APDU_START(0xDA)
    BUILD_APDU_INDEX(index)

    if (index == 0) timeout = 10000;
    else timeout = 100;

    APDUbuffer[4] = 0x00;
    APDUsize = 5;

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, timeout);
    ret = CheckResponseNoData(ret, "V2X_DeletePrivateKey", index);

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_keygen - Generate ECC public/private key pair.
// Private key stored on chip and indexed, public key returned to the host.
// Send Generate key pair APDU: CLA=80, INS=A0, P1P2=@KEYID, Le=00
// 80 A0 00 01 00
//-----------------------------------------------------------------------------
V2X_RESULT V2X_keygen(
               int          userid, // In: Admin/User ID
               PKAlgorithm  alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
               uint32_t     index,	// In:  index to use when storing generated private key (1...3000)
               ECPublicKey *pubkey) // Out: generated public key is copied to this pointer/address
{
    int ret;

    BUILD_APDU_ALGID(0xA0)
    BUILD_APDU_INDEX(index)

    APDUbuffer[4] = 0x00;
    APDUsize = 5;

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 500);
    Log_Timing = 0;

    if (!CheckResponse(ret, "V2X_keygen", index)) ret = 0;
    else if (pubkey != NULL) {
        if (pubkey->blob) memcpy(pubkey->blob, RESP_APDU, RESP_APDU_size);
        pubkey->len = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_import_public_key - Import public key.
// Public key stored on chip and indexed.
//
// Send Set Public Key APDU: CLA=80, INS=AD, P1P2=@KEYID, Lc=41 Data=@PublicKey
// 80 AD 00 01 41 04 ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230 28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
//-----------------------------------------------------------------------------
V2X_RESULT V2X_import_public_key(
                        int userid,             // In: Admin/User ID
                        PKAlgorithm  alg,	    // In: Algorithm/curve: ECC224/256/384 NIST/BP
                        uint32_t    index,	    // In: index to use when storing private key (1...3000)
                        ECPublicKey *pubkey)    // In: public key
{
    int ret;
    if ((int)pubkey->len > sizeof(APDUbuffer)-5) {
#ifdef DEBUG
        LogError("ERROR: V2X_import_public_key: Public key blob too big: len=%d\n", pubkey->len);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xAD)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(pubkey->blob, pubkey->len);

#ifdef DEBUG
    if (LogLevel > 1) Log("Import public key\n");
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);
    ret = CheckResponseNoData(ret, "V2X_import_public_key", index);


    return ret;
}
//-----------------------------------------------------------------------------
// V2X_import_private_key - Imports private key to V2X Prototype
// Private key stored on chip and indexed.
//
// Send Set Private Key APDU: CLA=80, INS=AE, P1P2=@KEYID, Lc=20 Data=@ChipPrivateKey-dIUT
// 80 AE 00 01 20 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
//------------------------------------------------------------------------------------
V2X_RESULT V2X_import_private_key(
                        int userid,             // In: Admin/User ID
                        PKAlgorithm  alg,	    // In: Algorithm/curve: ECC224/256/384 NIST/BP
                        uint32_t      index,	// In: index to use when storing private key (1...3000)
                        ECPrivateKey *prvkey)	// In: private key
{
    int ret;
    if ((int)prvkey->len > sizeof(APDUbuffer)-5) {
#ifdef DEBUG
        LogError("ERROR: V2X_import_private_key: Private key blob too big: len=%d\n", prvkey->len);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xAE)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(prvkey->blob, prvkey->len);

#ifdef DEBUG
    if (LogLevel > 1) Log("Import private key\n");
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);
    ret = CheckResponseNoData(ret, "V2X_import_private_key", index);

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_export_public_key - Exports public key from V2X Prototype
// Public key stored on chip and indexed.
//
// Send Get public Key APDU: CLA=80, INS=AC, P1P2=@KEYID, Le=00
// 80 AC 00 01 00
//------------------------------------------------------------------------------------
V2X_RESULT V2X_export_public_key(
                        int         userid,     // In: Admin/User ID
                        uint32_t    index,      // In: index to use when storing public key (1...3000)
                        ECPublicKey *pubkey)    // Out: buffer for public key
{
    int ret;

    BUILD_APDU_START(0xAC)
    BUILD_APDU_INDEX(index)

    APDUbuffer[4] = 0x00;
    APDUsize = 5;

#ifdef DEBUG
    if (LogLevel > 1) Log("Export public key\n");
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (pubkey) pubkey->len = 0;
    if (!CheckResponseIgnoreData(ret, "V2X_export_public_key", index)) ret = 0;
    else if (pubkey != NULL && RESP_APDU_size != 0) {
        memcpy(pubkey->blob, RESP_APDU, RESP_APDU_size);
        pubkey->len = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_export_private_key - Exports private key pair from V2X Prototype
// Private key stored on chip and indexed.
//
// Send Get Private Key APDU: CLA=80, INS=AF, P1P2=@KEYID, Le=00
// 80 AF 00 01 00
//------------------------------------------------------------------------------------
V2X_RESULT V2X_export_private_key(
                        int          userid,    // In: Admin/User ID
                        uint32_t     index,	    // In: index to use when storing private key (1...3000)
                        ECPrivateKey *prvkey)	// Out: buffer for private key
{
    int ret;

    BUILD_APDU_START(0xAF)
    BUILD_APDU_INDEX(index)

    APDUbuffer[4] = 0x00;
    APDUsize = 5;

#ifdef DEBUG
    if (LogLevel > 1) Log("Export private key\n");
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (prvkey) prvkey->len = 0;
    if (!CheckResponseIgnoreData(ret, "V2X_export_private_key", index)) ret = 0;
    else if (prvkey == NULL) ret = 1; // Key value ignored
    else if (RESP_APDU_size == 0) ret = 0; // Error exporting key from V2X Prototype
    else {
        memcpy(prvkey->blob, RESP_APDU, RESP_APDU_size);
        prvkey->len = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecdsa_fast_prepare - Pre-generate and store in V2X Prototype's RAM the fast signature
// generation data for a specified private key.
// Private key value is stored on chip and indexed.
//
// Send Cache fast signature data APDU: CLA=80, INS=A4, P1P2=@KEYID, Lc=00
// 80 A4 00 01 00
//------------------------------------------------------------------------------------
V2X_RESULT V2X_ecdsa_fast_prepare(
                           int          userid, // In: Admin/User ID
                           PKAlgorithm  alg,    // In: Algorithm/curve: ECC224/256/384 NIST/BP
                           uint32_t     index,  // In: index of a private key to cache for fast 2-steps signature
                           int          number) // In: number of pre-generated datasets for specified private key
{
    int ret;
    if (number < 0 || number > MAX_RAM_KEYS) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdsa_fast_prepare failed. Number (%d) out of range [1..%d] !!!\n", number, MAX_RAM_KEYS);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA4)
    BUILD_APDU_INDEX(index)

    APDUsize = 4;
    if (number == 0) APDUbuffer[APDUsize++] = 0x00;
    else {
        APDUbuffer[APDUsize++] = 0x01;
        APDUbuffer[APDUsize++] = (BYTE)number;
        APDUbuffer[APDUsize++] = 0x00; // Le
    }
    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 30 * number);
    Log_Timing = 0;

    ret = CheckResponseNoData(ret, "V2X_ecdsa_fast_prepare", index);

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecdsa_fast_sign - Generate Fast ECDSA signature.
// Used to sign emergency messages using data cache prepared for fast signing (V2X_ecdsa_fast_prepare).
// Stored (indexed) private key used to sign message's hash received from the host.
//
// Send ECDSA sign APDU: CLA=80, INS=A5, P1P2=@KEYID, Lc=20 Data=Digest
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecdsa_fast_sign(
                    int         userid,     // In: Admin/User ID
                    PKAlgorithm alg,	    // In:  Algorithm/curve: ECC224/256/384 NIST/BP
                    uint32_t    index,	    // In:  private key index to use in ECDSA (1...65535)
                    uint8_t     const *dgst,// In: The digest to sign
                    size_t      dgstLen,	// In: The length of the dgst buffer
                    uint8_t     *sig,	    // Out: Returns the signature encoded as a byte array
                    size_t      *sigLen)	// Out: Returns the number of bytes in sig
{
    int ret;
    if ((int)dgstLen > DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdsa_fast_sign: Digest too big: dgstLen=%d\n", dgstLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA5)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(dgst, dgstLen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);

    if (!CheckResponse(ret, "V2X_ecdsa_fast_sign", index)) ret = 0;
    else {
        if (sig) memcpy(sig, RESP_APDU, RESP_APDU_size);
        if (sigLen) *sigLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecdsa_slow_sign - Generate regular speed ECDSA signature (~40 ms)
// Used to sign non-emergency messages to save data cache prepared for fast signing.
// Stored (indexed) private key used to sign message's hash received from the host.
//
// Send ECDSA sign APDU: CLA=80, INS=AA, P1P2=@KEYID, Lc=20 Data=Digest
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecdsa_slow_sign(
                    int         userid,     // In: Admin/User ID
                    PKAlgorithm alg,	    // In: Algorithm/curve: ECC224/256/384 NIST/BP
                    uint32_t    index,	    // In: private key index to use in ECDSA (1...3000)
                    uint8_t     const *dgst,// In: The digest to sign
                    size_t      dgstLen,	// In: The length of the dgst buffer
                    uint8_t     *sig,	    // Out: Returns the signature encoded as a byte array
                    size_t      *sigLen)	// Out: Returns the number of bytes in sig
{
    int ret;
    if ((int)dgstLen > DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdsa_fast_sign: Digest too big: dgstLen=%d\n", dgstLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xAA)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(dgst, dgstLen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);

    if (!CheckResponse(ret, "V2X_ecdsa_slow_sign", index)) ret = 0;
    else {
        if (sig) memcpy(sig, RESP_APDU, RESP_APDU_size);
        if (sigLen) *sigLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecdsa_sign - Generate standard ECDSA signature.
// Stored (indexed) private key used to sign message's hash received from the host.
//
// Send ECDSA sign APDU: CLA=80, INS=A1, P1P2=@KEYID, Lc=20 Data=Digest
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecdsa_sign(
                    int         userid,     // In: Admin/User ID
                    PKAlgorithm alg,	    // In:  Algorithm/curve: ECC224/256/384 NIST/BP
                    uint32_t    index,	    // In:  private key index to use in ECDSA (1...3000)
                    uint8_t     const *dgst,// In: The digest to sign
                    size_t      dgstLen,	// In: The length of the dgst buffer
                    uint8_t     *sig,	    // Out: Returns the signature encoded as a byte array
                    size_t      *sigLen)	// Out: Returns the number of bytes in sig
{
    int ret;
    if ((int)dgstLen > DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdsa_sign: Digest too big: dgstLen=%d\n", dgstLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA1)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(dgst, dgstLen);

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    Log_Timing = 0;

    if (!CheckResponse(ret, "V2X_ecdsa_sign", index)) ret = 0;
    else {
        if (sig) memcpy(sig, RESP_APDU, RESP_APDU_size);
        if (sigLen) *sigLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecdsa_verify - Verify standard ECDSA signature.
// Stored (indexed) public key used to verify message's hash received from the host.
//
// Send ECDSA verify APDU: CLA=80, INS=A2, P1P2=@KEYID, Lc=65 Data=81 Len Hash 82 Len 02/03 || r || s
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecdsa_verify(
                    int         userid,     // In: Admin/User ID
                    PKAlgorithm alg,	    // In:  Algorithm/curve: ECC224/256/384 NIST/BP
                    uint32_t    index,	    // In: Public key index to use in ECDSA (1...3000)
                    uint8_t   const *dgst,	// In: The digest to verify
                    size_t    dgstLen,	    // In: The length of the dgst buffer
                    uint8_t   *sig,	        // In: The signature encoded as a byte array
                    size_t    sigLen)	    // In: The number of bytes in sig
{
    int ret;
    if ((int)dgstLen > DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdsa_verify: Digest too big: dgstLen=%d\n", dgstLen);
#endif
        errorflag=1;
        return 0;
    }
    if ((int)sigLen > SIGNATURE_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdsa_verify: Signature too big: sigLen=%d\n", sigLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA2)
    BUILD_APDU_INDEX(index)

    APDUsize = 5; // Only short Lc supported here!
    BUILD_APDU_ADD_TAG(0x81, dgst, dgstLen)
    BUILD_APDU_ADD_TAG(0x82, sig, sigLen)

    APDUbuffer[4] = (BYTE)APDUsize - 5;
    APDUbuffer[APDUsize++] = 0x00; // Le

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    Log_Timing = 0;

    ret = CheckResponseNoData(ret, "V2X_ecdsa_verify", index);

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecdh_derivation - generate a shared secret using stored (indexed) private key for host-based ECIES for data decryption.
//
// Send ECDH APDU: CLA=80, INS=A3, P1P2=@KEYID, Lc=41 Data=@HostPublicKey (04 X || Y)
// 80 A3 00 01 41 04 700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287 db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecdh_derivation(
                        int         userid, // In: Admin/User ID
                        PKAlgorithm alg,	// In:  Algorithm/curve: ECC224/256/384 NIST/BP
                        uint32_t    index,	// In:  private key index to use in ECDSA  (1...3000)
                        ECPublicKey *pubkey,// In: sender/recipient public key
                        uint8_t     *secret,// Out: Returns the shared secret encoded as a byte array
                        size_t      *secLen)// Out: Returns the number of bytes in secret
{
    int ret;
    if ((int)pubkey->len > sizeof(APDUbuffer)-5) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdh_derivation: Public key blob too big: len=%d\n", pubkey->len);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA3)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(pubkey->blob, pubkey->len);

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    Log_Timing = 0;

    if (!CheckResponse(ret, "V2X_ecdh_derivation", index)) ret = 0;
    else if (RESP_APDU_size != ECDH_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecdh_derivation: Shared secret size incorrect: len=%d\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else {
        if (secret) memcpy(secret, RESP_APDU, RESP_APDU_size);
        if (secLen) *secLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecqv_reception - reconstruct private key using stored private key and e,r,f values.
//
// CLA=80, INS=A6, P1P2=@KeyIndex1, Lc=XX Data=82 || 02 || Key index 2 || 83 || Len || e 84 || Len || r 85 || Len || f (optional)
// 80 A6 00 01 ...
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecqv_reception(
                        int         userid, // In: Admin/User ID
                        PKAlgorithm alg,    // In:  Algorithm/curve: ECC224/256/384 NIST/BP
                        uint32_t    index1,	// In:  private key kU index to use in reconstruction (1...3000)
                        uint32_t    index2,	// In:  index to use when storing reconstructed private key dU (1...3000)
                        uint8_t   const *e,	// In: The digest of CertU mod n
                        size_t        eLen,	// In: The length of the e buffer
                        uint8_t   const *r,	// In: reconstruction value r
                        size_t        rLen,	// In: The length of the r
                        uint8_t   const *f,	// In: Optional: f() for butterfly keys. NULL if not used
                        size_t        fLen,	// In: Optional: The length of the f buffer. Zero if not used
                        ECPublicKey *pubkey)// Out: Reconstructed public key is copied to this pointer/address
{
    int ret;
    if ((int)eLen > DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecqv_reception: e too big: eLen=%d\n", eLen);
#endif
        errorflag=1;
        return 0;
    }
    if ((int)rLen > ECC_COORD_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecqv_reception: r too big: rLen=%d\n", rLen);
#endif
        errorflag=1;
        return 0;
    }
    if ((int)fLen > ECC_COORD_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecqv_reception: f too big: fLen=%d\n", fLen);
#endif
        errorflag=1;
        return 0;
    }
    //if (e == NULL || (int)eLen == 0) {LogError("ERROR: V2X_ecqv_reception: e is NULL\n"); errorflag=1; return 0; }
    //if (r == NULL || (int)rLen == 0) {LogError("ERROR: V2X_ecqv_reception: r is NULL\n"); errorflag=1; return 0; }


    BUILD_APDU_ALGID(0xA6)
    BUILD_APDU_INDEX(index1)

    APDUsize = 5; // Only short Lc supported here!

    APDUbuffer[APDUsize++] = 0x82;
    APDUbuffer[APDUsize++] = 0x02;
    APDUbuffer[APDUsize++] = (BYTE)(index2 >> 8);     // High byte of key index 2
    APDUbuffer[APDUsize++] = (BYTE)(index2 & 0x00FF); // Low byte of key index 2

    BUILD_APDU_ADD_TAG(0x83, e, eLen)
    BUILD_APDU_ADD_TAG(0x84, r, rLen)

    if (f && fLen) { // Butterfly function f() is optional, can be NULL
        BUILD_APDU_ADD_TAG(0x85, f, fLen)
    }
    APDUbuffer[4] = (BYTE)APDUsize - 5;
    APDUbuffer[APDUsize++] = 0x00; // Le

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    Log_Timing = 0;

    if (!CheckResponse(ret, "V2X_ecqv_reception", index1)) ret = 0;
    else if (pubkey == NULL) ret = 1;
    else if (RESP_APDU_size > ECC_PUB_KEY_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecqv_reception: returned reconstructed public too big: %d bytes\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else {
        if (pubkey->blob) memcpy(pubkey->blob, RESP_APDU, RESP_APDU_size);
        pubkey->len = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_digest - calculate hash/digest in V2X Prototype
// Send Digest APDU: 80 50 00 00 Lc data
//-----------------------------------------------------------------------------
V2X_RESULT V2X_digest(
                int      userid,        // In:  Admin/User ID
                BYTE     algID,		    // In:  Algorithm: 04=SHA256
                BYTE     *message,		// In:  message to digest
                size_t   messageLen,	// In:  message length
                BYTE     *digest,		// Out: Returns the hash of the message
                size_t   *digestLen)	// Out: Returns the number of bytes in digest
{
    int ret;
    if ((int)messageLen > sizeof(APDUbuffer)-5) {
#ifdef DEBUG
        LogError("ERROR: V2X_digest: Message too big: len=%d\n", messageLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_START(0x50)
    APDUbuffer[2] = 0x00;
    APDUbuffer[3] = 0x00;
    ShortOrExtendedLength(message, messageLen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (!CheckResponse(ret, "V2X_digest", 0)) ret = 0;
    else if (RESP_APDU_size != DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_digest: Digest size incorrect: len=%d\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else {
        if (digest) memcpy(digest, RESP_APDU, RESP_APDU_size);
        if (digestLen) *digestLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_HMAC - calculate HMAC in V2X Prototype
// Send Digest APDU: 80 51 00 00 Lc data
//-----------------------------------------------------------------------------
V2X_RESULT V2X_HMAC(
                int      userid,        // In: Admin/User ID
                uint32_t index,	        // In:  secret key index to use in HMAC
                BYTE     *message,		// In:  message to digest
                size_t   messageLen,	// In:  message length
                BYTE     *digest,		// Out: Returns the hash of the message
                size_t   *digestLen)	// Out: Returns the number of bytes in digest
{
    int ret;
    if ((int)messageLen > sizeof(APDUbuffer)-5) {
#ifdef DEBUG
        LogError("ERROR: V2X_HMAC: Message too big: len=%d\n", messageLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_START(0x51)
    BUILD_APDU_INDEX(index)
    ShortOrExtendedLength(message, messageLen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (!CheckResponse(ret, "V2X_HMAC", index)) ret = 0;
    else if (RESP_APDU_size != DIGEST_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_HMAC: Digest size incorrect: len=%d\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else {
        if (digest) memcpy(digest, RESP_APDU, RESP_APDU_size);
        if (digestLen) *digestLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_KDF2 - calculate KDF2 in V2X Prototype
// Send KDF2 APDU: 80 52 00 00 Lc 83 || Len || SharedSecret || 84 || Len || KDP
//-----------------------------------------------------------------------------
V2X_RESULT V2X_KDF2(
                int      userid,        // In: Admin/User ID
                BYTE     *sharedSecret,	// In:  secret
                size_t   secretLen,		// In:  secret length
                BYTE     *kdp,		    // In:  key derivation parameter
                size_t    kdpLen,		// In:  key derivation parameter length
                size_t    derivedLen,	// In:  expected derived key length
                BYTE     *derivedKey)	// Out: Returns the derived key
{
    int ret;

    BUILD_APDU_START(0x52)
    APDUbuffer[2] = 0x00;
    APDUbuffer[3] = 0x00;

    APDUsize = 5; // Only short Lc supported here!
    BUILD_APDU_ADD_TAG(0x83, sharedSecret, secretLen)
    BUILD_APDU_ADD_TAG(0x84, kdp, kdpLen)

    APDUbuffer[4] = (BYTE)APDUsize - 5;
    APDUbuffer[APDUsize++] = (BYTE)derivedLen; // Le = expected derived key length

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (!CheckResponse(ret, "V2X_KDF2", 0)) ret = 0;
    else if (RESP_APDU_size != derivedLen) {
#ifdef DEBUG
        LogError("ERROR: V2X_KDF2: Derived key size incorrect: len=%d\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else
        if (derivedKey) memcpy(derivedKey, RESP_APDU, RESP_APDU_size);

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_ecies_encrypt - encrypt data using ECIES algorithm and provided
//   recipient public key and key derivation parameter P1.
//   Ephemeral public/private key pair is generated internally
//   Returns encrypted data and authentication tag.
//
// Send APDU: CLA=80, INS=A8, P1P2=0000, Lc=Var
//               Data=83 || Len || Recipient Public key(02/03 || X  or  04 || X || Y)
//                    84 || Len || KDP
//                    85 || Len || Plain data
// Response:          86 || Len || Ephemeral public key (04 || X || Y)
//                    87 || Len || Encrypted data
//                    88 || Len || Authentication Tag
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecies_encrypt(
                    int                 userid,     // In: Admin/User ID
                    PKAlgorithm         alg,        // In: Algorithm/curve: ECC224/256/384 NIST/BP
                    ECPublicKey        *pubkey,	    // In: Recipient public key
                    uint8_t     const  *kdp,	    // In: The key derivation parameter KDP (P1)
                    size_t              kdpLen,	    // In: The length of the key derivation parameter
                    uint8_t     const  *plaindata,  // In: The plain data
                    size_t              plainLen,	// In: The length of the plain data
                    uint8_t            *encrdata,	// Out: Returns the encrypted data encoded as a byte array
                    size_t             *encrLen,	// Out: Returns the number of bytes in encrypted data
                    uint8_t            *tag,	    // Out: The authentication tag
                    size_t             *tagLen,	    // Out: The length of the authentication tag
                    uint8_t            *ephpubkey,  // Out: The ephemeral public key blob
                    size_t             *ephkeyLen)  // Out: The length of the ephemeral public key blob
{
    int ret, cnt;
    if (encrLen) *encrLen = 0;

    if ((int)kdpLen > 255) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecies_encrypt: KDP too big: %d bytes\n", kdpLen);
#endif
        errorflag=1;
        return 0;
    }
    if ((int)plainLen > 255) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecies_encrypt: Encr.data too big: %d bytes\n", encrLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA8)
    APDUbuffer[2] = (BYTE)(ECIES_GenerateEphemeralKey >> 8);
    APDUbuffer[3] = (BYTE)(ECIES_GenerateEphemeralKey & 0x00FF);

    APDUsize = 5; // Only short Lc supported here!
    BUILD_APDU_ADD_TAG(0x83, pubkey->blob, pubkey->len)
    BUILD_APDU_ADD_TAG(0x84, kdp, kdpLen)
    BUILD_APDU_ADD_TAG(0x85, plaindata, plainLen)

    APDUbuffer[4] = (BYTE)APDUsize - 5;
    APDUbuffer[APDUsize++] = 0x00; // Le

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    Log_Timing = 0;

    if (!CheckResponse(ret, "V2X_ecies_encrypt", 0)) ret = 0;
    else {
        // Parse response
        cnt = 0;
        if (cnt < RESP_APDU_size && RESP_APDU[cnt++] == 0x86) { // Tag 86
            APDUsize = (int)RESP_APDU[cnt++];                   // Len
            if (cnt + APDUsize <= RESP_APDU_size) {             // ephemeral public key
                if (ephpubkey) memcpy(ephpubkey, &RESP_APDU[cnt], APDUsize);
                if (ephkeyLen) *ephkeyLen = APDUsize;
            }
            cnt += APDUsize;
        }
        if (cnt < RESP_APDU_size && RESP_APDU[cnt++] == 0x87) { // Tag 87
            APDUsize = (int)RESP_APDU[cnt++];                   // Len
            if (cnt + APDUsize <= RESP_APDU_size) {             // Encrypted data
                if (encrdata) memcpy(encrdata, &RESP_APDU[cnt], APDUsize);
                if (encrLen) *encrLen = APDUsize;
            }
            cnt += APDUsize;
        }
        if (cnt < RESP_APDU_size && RESP_APDU[cnt++] == 0x88) { // Tag 88
            APDUsize = (int)RESP_APDU[cnt++];                   // Len
            if (cnt + APDUsize <= RESP_APDU_size) {             // Auth Tag
                if (tag) memcpy(tag, &RESP_APDU[cnt], APDUsize);
                if (tagLen) *tagLen = APDUsize;
            }
        }
    }

    return ret;
}

//-----------------------------------------------------------------------------
// V2X_ecies_decrypt - decrypt ECIES encrypted data using stored (indexed)
//   recipient private key and provided ephemeral public key and key derivation
//   parameter P1, and authenticate data using provided tag
//
// Send APDU: CLA=80, INS=A9, P1P2=@KEYID, Lc=Var
//               Data=83 || Len || Ephemeral Public key(02/03 || X  or  04 || X || Y)
//                    84 || Len || KDP
//                    85 || Len || Encr.data
//                    86 || Len || Tag (optional)
//-----------------------------------------------------------------------------
V2X_RESULT V2X_ecies_decrypt(
                    int                 userid,     // In: Admin/User ID
                    PKAlgorithm         alg,        // In: Algorithm/curve: ECC224/256/384 NIST/BP
                    uint32_t            index,	    // In: private key index to use in ECIES (1...3000)
                    ECPublicKey        *pubkey,	    // In: ephemeral public key
                    uint8_t     const  *kdp,	    // In: The key derivation parameter KDP (P1)
                    size_t              kdpLen,	    // In: The length of the key derivation parameter
                    uint8_t     const  *encrdata,   // In: The encrypted data
                    size_t              encrLen,	// In: The length of the encrypted data
                    uint8_t     const  *tag,	    // In: The authentication tag
                    size_t              tagLen,	    // In: The length of the authentication tag
                    uint8_t            *plaindata,	// Out: Returns the decrypted data encoded as a byte array
                    size_t             *plainLen)	// Out: Returns the number of bytes in decrypted data
{
    int ret;
    if ((int)kdpLen > 255) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecies_decrypt: KDP too big: %d bytes\n", kdpLen);
#endif
        errorflag=1;
        return 0;
    }
    if ((int)encrLen > 255) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecies_decrypt: Encr.data too big: %d bytes\n", encrLen);
#endif
        errorflag=1;
        return 0;
    }
    if ((int)tagLen > ECIES_TAG_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_ecies_decrypt: Tag too big: %d bytes\n", tagLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xA9)
    BUILD_APDU_INDEX(index)

    APDUsize = 5; // Only short Lc supported here!
    BUILD_APDU_ADD_TAG(0x83, pubkey->blob, pubkey->len)
    BUILD_APDU_ADD_TAG(0x84, kdp, kdpLen)
    BUILD_APDU_ADD_TAG(0x85, encrdata, encrLen)
    BUILD_APDU_ADD_TAG(0x86, tag, tagLen)

    APDUbuffer[4] = (BYTE)APDUsize - 5;
    APDUbuffer[APDUsize++] = 0x00; // Le

    Log_Timing = 1;
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 200);
    Log_Timing = 0;

    if (!CheckResponse(ret, "V2X_ecies_decrypt", index)) ret = 0;
    else {
        if (plaindata) memcpy(plaindata, RESP_APDU, RESP_APDU_size);
        if (plainLen) *plainLen = RESP_APDU_size;
    }

    return ret;
}
//-----------------------------------------------------------------------------
// V2X_AES_encrypt - encrypt data using AES algorithm and AES key stored on V2X Prototype
//                   Key index provided in P1P2.
//                   Returns encrypted data.
//
// Send APDU: CLA=80, INS=81, P1P2=KeyID, Lc=Var Data=Plain data
// Response:          Encrypted data
//-----------------------------------------------------------------------------
V2X_RESULT V2X_AES_encrypt(
                    int                 userid,     // In: Admin/User ID
                    uint32_t            index,	    // In: Encr. key index in V2X Prototype NVM (0 - 7)
                    uint8_t     const  *plaindata,  // In: The plain data
                    size_t              plainLen,	// In: The length of the plain data
                    uint8_t            *encrdata,	// Out: Returns the encrypted data encoded as a byte array
                    size_t             *encrLen)	// Out: Returns the number of bytes in encrypted data
{
    int ret;
    int kid = (int)index;
    if (kid >= NVM_OFFSET_PASSWORDS) kid -= NVM_OFFSET_PASSWORDS;
    if (kid >= MAX_NVM_FILES) {
#ifdef DEBUG
        LogError("ERROR: V2X_AES_encrypt: Incorrect key ID: %X\n", index);
#endif
        errorflag=1;
        return 0;
    }
    if (encrLen) *encrLen = 0;

    if ((int)plainLen > MAX_DATA_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_AES_encrypt: Plain.data too big: %d bytes\n", plainLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_CLA(0x8A, 0x11) // 0x89: AES128, 0x8A: AES256
    BUILD_APDU_INDEX(kid)
    ShortOrExtendedLength((BYTE*)plaindata, plainLen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (!CheckResponse(ret, "V2X_AES_encrypt", index)) ret = 0;
    else if (RESP_APDU_size <= 0) {
#ifdef DEBUG
        LogError("ERROR: V2X_AES_encrypt: Encrypted data size incorrect: len=%d\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else {
        if (encrdata) memcpy(encrdata, RESP_APDU, RESP_APDU_size);
        if (encrLen) *encrLen = RESP_APDU_size;
    }

    return ret;
}

//-----------------------------------------------------------------------------
// V2X_AES_decrypt - decrypt data using AES algorithm and AES key stored on V2X Prototype
//                   Key index provided in P1P2.
//                   Returns decrypted data.
//
// Send APDU: CLA=80, INS=82, P1P2=KeyID, Lc=Var Data=encrypted data
// Response:          Plain data
//-----------------------------------------------------------------------------
V2X_RESULT V2X_AES_decrypt(
                    int                 userid,		// In: Admin/User ID
                    uint32_t            index,		// In: Encr. key index in V2X Prototype NVM (0 .. 7 or 0xF000 .. 0xF007)
                    uint8_t     const  *encrdata,	// In: encrypted data encoded as a byte array
                    size_t              encrLen,	// In: the number of bytes in encrypted data
                    uint8_t            *plaindata,	// Out: The plain data
                    size_t             *plainLen)	// Out: the pointer to the length of the plain data
{
    int ret;
    int kid = (int)index;
    if (kid >= NVM_OFFSET_PASSWORDS) kid -= NVM_OFFSET_PASSWORDS;
    if (kid >= MAX_NVM_FILES) {
#ifdef DEBUG
        LogError("ERROR: V2X_AES_decrypt: Incorrect key ID: %X\n", index);
#endif
        errorflag=1;
        return 0;
    }
    if (plainLen) *plainLen = 0;

    if ((int)encrLen > MAX_DATA_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_AES_decrypt: Encr.data too big: %d bytes\n", encrLen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_CLA(0x8A, 0x12) // AES256
    BUILD_APDU_INDEX(kid)
    ShortOrExtendedLength(encrdata, encrLen);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (!CheckResponse(ret, "V2X_AES_decrypt", index)) ret = 0;
    else if (RESP_APDU_size <= 0) {
#ifdef DEBUG
        LogError("ERROR: V2X_AES_decrypt: Decrypted data size incorrect: len=%d\n", RESP_APDU_size);
#endif
        errorflag=1;
        ret = 0;
    }
    else {
        if (plaindata) memcpy(plaindata, RESP_APDU, RESP_APDU_size);
        if (plainLen) *plainLen = RESP_APDU_size;
    }

    return ret;
}

//-----------------------------------------------------------------------------
// Send ECHO APDU - for interface testing
// Parameters:
//  Input:	none
//  Returns: V2X_SUCCESS or error code
//-----------------------------------------------------------------------------
V2X_RESULT V2X_echo(int     userid,     // In: Admin/User ID
                    BYTE    *data,      // In: data to send
                    int     datasize,   // In: sent data size
                    UINT16  delay,      // In: response delayed by V2X Prototype in ms(sent as P1P2 parameter)
                    BYTE    *response,  // Out: array for response
                    int     *respsize)  // Out: response size
{
    int ret;

    if (V2X_FirmwareVersion < 200) { BUILD_APDU_CLA(0xC2, 0x21)}
    else                           { BUILD_APDU_CLA(0x80, 0x21)}
    BUILD_APDU_INDEX(delay)
    ShortOrExtendedLength(data, datasize);

    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);
    if (!CheckResponse(ret, "V2X_echo", 0)) ret = 0;
    if (response && RESP_APDU_size != 0) memmove(response, RESP_APDU, RESP_APDU_size);
    if (respsize) *respsize = RESP_APDU_size;


    return ret;
}

//-----------------------------------------------------------------------------
// Send GetRandom APDU - returns V2X Prototype-generated random number
// Parameters:
//  Input:	length of requested random in bytes
//  Input:	pointer to a reserved buffer for the random
//  Output: Random number copied to the reserved buffer
//-----------------------------------------------------------------------------
V2X_RESULT V2X_GetRandom(
    int     userid,     // In: Admin/User ID
    BYTE    len,        // In: the size of the random data
    BYTE    *buffer)    // Out: pointer to a buffer for the generated random data
{
    int ret;
    BYTE GetRandomAPDU[] = {0x80, 0x84, 0x00, 0x00, (BYTE)len };


    ret = V2X_send_apdu(userid, GetRandomAPDU, sizeof(GetRandomAPDU), RESP_APDU, &RESP_APDU_size, 200);
    if (!CheckResponse(ret, "V2X_GetRandom", 0)) ret = 0;
    else {
        if (buffer) memcpy(buffer, RESP_APDU, RESP_APDU_size);
    }

    return ret;
}

//-----------------------------------------------------------------------------
// V2X_write_file - Write file to V2X Prototype NVM.
// File stored on chip and indexed.
//
// Send Write File APDU: CLA=80, INS=D6, P1P2=@FileID, Lc Data
// 80 D6 00 01  05  01 02 03 04 05
//-----------------------------------------------------------------------------
V2X_RESULT V2X_write_file(
	int         userid,     // In: Admin/User ID
	uint16_t    fileid,     // In: file index (0...9, E000...E009)
	BYTE       *info,	// In: file data
	int         infolen)    // In: data size
{
    int ret;
    int fid = (int)fileid;
    if (fid >= NVM_OFFSET_FILES) fid -= NVM_OFFSET_FILES;
    if (fid >= MAX_NVM_FILES) {
#ifdef DEBUG
        LogError("ERROR: V2X_write_file: Incorrect File ID: %d\n", fileid);
#endif
        errorflag=1;
        return 0;
    }
    if (infolen > MAX_FILE_DATA_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_write_file: File size exceeds APDU size: len=%d\n", infolen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_START(0xD6)
    BUILD_APDU_INDEX(fid)
    ShortOrExtendedLength(info, infolen);

#ifdef DEBUG
    if (LogLevel > 1) Log("Write file\n");
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);
    ret = CheckResponseNoData(ret, "V2X_write_file", fileid);


    return ret;
}
//-----------------------------------------------------------------------------
// V2X_read_file - Reads file from V2X Prototype NVM
// File stored on chip and indexed.
//
// Send Get public Key APDU: CLA=80, INS=B0, P1P2=@FileID, Le=00
// 80 B0 00 01 00
//------------------------------------------------------------------------------------
V2X_RESULT V2X_read_file(
	int         userid,	// In: Admin/User ID
	uint16_t    fileid,	// In: file index (0...9)
	BYTE       *info,	// Out: buffer for the retrieved file data
	int        *infolen)	// Out: pointer to a variable which will get the retrieved data size
{
    int ret;
    int fid = (int)fileid;
    if (fid >= NVM_OFFSET_FILES) fid -= NVM_OFFSET_FILES;
    if (fid >= MAX_NVM_FILES) {
#ifdef DEBUG
        LogError("ERROR: V2X_read_file: Incorrect File ID: %d\n", fileid);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_START(0xB0)
    BUILD_APDU_INDEX(fid)

    APDUbuffer[4] = 0x00;
    APDUsize = 5;

#ifdef DEBUG
    if (LogLevel > 1) Log("Read file\n");
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);

    if (infolen) *infolen = 0;
    if (!CheckResponseIgnoreData(ret, "V2X_read_file", fileid)) ret = 0;
    else if (info != NULL && RESP_APDU_size != 0) {
        memcpy(info, RESP_APDU, RESP_APDU_size);
    }
    if (infolen) *infolen = RESP_APDU_size;

    return ret;
}

//-----------------------------------------------------------------------------
// V2X_change_user_key  - Change admin or user password or symmetric transport key.
// Password/Key stored in V2X Prototype NVM and indexed.
//
// Send IMPORT PRIVATE APDU: CLA=80, INS=AE, P1P2=@KEYID, Lc=xx Data=Password
// 80 AE F0 01   05   12 34 56 78 9A
//------------------------------------------------------------------------------------
V2X_RESULT V2X_change_user_key (
    int         userid, // In: Admin/User ID
    BYTE        alg,	// In: Algorithm: 0x08-HMAC, 0x0A-AES256
    uint16_t    keyid,	// In: Admin/user password/key index key/passwords (0...7)
    BYTE        *key,	// In: pointer to a password/key byte array
    int         keylen)	// In: password/key size in bytes
{
    int ret;
    int kid = (int)keyid;
    if (kid >= NVM_OFFSET_PASSWORDS) kid -= NVM_OFFSET_PASSWORDS;
    if (kid >= MAX_USERS) {
#ifdef DEBUG
        LogError("ERROR: V2X_change_user_key: Incorrect Key ID: %d\n", keyid);
#endif
        errorflag=1;
        return 0;
    }
    if (keylen > USER_KEY_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_change_user_key: Password/key too big: len=%d\n", keylen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_ALGID(0xAE)                      // CLA INS
    BUILD_APDU_INDEX(kid+NVM_OFFSET_PASSWORDS)// P1 P2
    ShortOrExtendedLength(key, keylen);

#ifdef DEBUG
    if (LogLevel > 1) Log("Change user key %04X\n", kid);
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);
    ret = CheckResponseNoData(ret, "V2X_change_user_key", keyid);

    return ret;
}

//-----------------------------------------------------------------------------
// Get V2X Prototype's Files/keys/Lifecycle Access Conditions (8xN bytes)
// Parameters:
// Input:	mode:   0x00 - get files access conditions array
//	                0x01 - get keys access conditions array
//	                0x02 - get V2X Prototype life cycle access conditions array
// Output:  access conditions copied to the output buffer
//-----------------------------------------------------------------------------
V2X_RESULT V2X_get_access_conditions(
    int     userid, // In: Admin/User ID
    BYTE    mode,   // In:  mode
    char    *buffer)// Out: access conditions array copied to the output buffer
{
    int ret;
    BYTE GetDataAPDU[] = {0x80, 0xCA, mode, 0x80, 0x00 };

    ret = V2X_send_apdu(userid, GetDataAPDU, sizeof(GetDataAPDU), RESP_APDU, &RESP_APDU_size, 50);
    if (!CheckResponse(ret, "V2X_GetAccessConditions", 0)) ret = 0;
    else {
        if (buffer) memcpy(buffer, RESP_APDU, RESP_APDU_size);
    }

    return RESP_APDU_size;
}

//-----------------------------------------------------------------------------
// V2X_change_access_conditions - Change file or key or V2X Prototype life cycle access conditions.
// Access conditions stored in V2X Prototype NVM associated with respective file or key.
//
// Send CHANGE AC APDU: CLA=y8, INS=DB, P1P2=@KEYID, Lc=08 Data=@ACarray
// 80 DB XX XX   08   XX XX XX XX XX XX XX XX
//------------------------------------------------------------------------------------
V2X_RESULT V2X_change_access_conditions(
    int         userid, // In: Admin/User ID
    uint16_t	index,	// In: fileID (0, 0xE000 ... 0xE009) or keyID (0xF000...0xF007)
                        //     or Lifecycle AC (0xFFFF)
    BYTE	*ac,	// In: pointer to a new access conditions array (8 bytes)
    int		aclen)	// In: access conditions array size in bytes
{
    int ret;
    if ((index > 0 && index < NVM_OFFSET_FILES) ||
        (index >= NVM_OFFSET_FILES+MAX_NVM_FILES && index < NVM_OFFSET_PASSWORDS) ||
        (index >= NVM_OFFSET_PASSWORDS+MAX_USERS && index < NVM_OFFSET_LIFECYCLE)) {
#ifdef DEBUG
        LogError("ERROR: V2X_change_access_conditions: Incorrect Key/File ID: %d\n", index);
#endif
        errorflag=1;
        return 0;
    }
    if (aclen != AC_SIZE) {
#ifdef DEBUG
        LogError("ERROR: V2X_change_access_conditions: Incorrect Access Condition array size: len=%d\n", aclen);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_START(0xDB)                  // CLA INS
    BUILD_APDU_INDEX(index)                 // P1 P2
    ShortOrExtendedLength(ac, aclen);

#ifdef DEBUG
    if (LogLevel > 1) Log("Change access conditions for %04X\n", index);
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 100);
    ret = CheckResponseNoData(ret, "V2X_change_access_conditions", index);

    return ret;
}

//-----------------------------------------------------------------------------
// Get current V2X Prototype life cycle state
// Parameters:
//  Input:	none
//  Output: life cycle state 1-Manufacturing, 4-Initialization, 0x10-operation
//-----------------------------------------------------------------------------
int V2X_get_lifecycle_state(int userid)     // In: Admin/User ID
{
    int ret;
    BYTE GetDataAPDU[] = {0x80, 0xCA, 0x00, 0x02, 0x00 };

    ret = V2X_send_apdu(userid, GetDataAPDU, sizeof(GetDataAPDU), RESP_APDU, &RESP_APDU_size, 50);
    if (CheckResponse(ret, "V2X_get_lifecycle", 0)) ret = (int)RESP_APDU[0];
    else ret = 0;

    return ret;
}

//-----------------------------------------------------------------------------
// V2X_change_life_cycle - Change V2X Prototype chip life cycle state. Requires authentication.
//
// Send CHANGE LIFE CYCLE APDU: CLA=y0, INS=F0, P1=00 P2=@LifeCycle, Le=00
// 00 F0 00 10   00
//------------------------------------------------------------------------------------
V2X_RESULT V2X_change_life_cycle (
    int     userid,     // In: Admin/User ID
    BYTE    lifecycle)  // In: new life cycle state
{
    int ret;
    if (lifecycle != LIFECYCLE_MANUFACTURING &&
        lifecycle != LIFECYCLE_INITIALIZATION &&
        lifecycle != LIFECYCLE_OPERATION) {
#ifdef DEBUG
        LogError("ERROR: V2X_change_life_cycle: Incorrect life cycle state to %X\n", lifecycle);
#endif
        errorflag=1;
        return 0;
    }

    BUILD_APDU_START(0xF0)                      // CLA INS
    BUILD_APDU_INDEX((unsigned short)lifecycle) // P1 P2
    APDUbuffer[4] = 0x00;                       // Le
    APDUsize = 5;

#ifdef DEBUG
    if (LogLevel > 1) Log("Change V2X Prototype life cycle state to %X\n", lifecycle);
#endif
    ret = V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 1000);
    ret = CheckResponseNoData(ret, "V2X_change_life_cycle", lifecycle);

    return ret;
}

//-------------------------------------------------------------------------------
//	Execute Write Firmware Update command (y0 F2 <P1P2=Block number> 00 Lc Lc <Data> Le Le)
//	Send command APDU receive response APDU, check returned SW1 SW2 code.
//-------------------------------------------------------------------------------
int V2X_WriteFirmware(int     userid,     // In: Admin/User ID
                      int     blocknr,    // In: NVM page number
                      BYTE    *data,      // In: data to write
                      int     len)        // In: data length
{
    BUILD_APDU_START(0xF2)
    BUILD_APDU_INDEX(blocknr)
    ShortOrExtendedLength(data, len);

    if (V2X_send_apdu(userid, APDUbuffer, APDUsize, RESP_APDU, &RESP_APDU_size, 20) &&
        RESP_APDU[RESP_APDU_size-2] == 0x90 && RESP_APDU[RESP_APDU_size-1] == 0x00)
    {
        return 1;
    }
    return 0;
}

//-------------------------------------------------------------------------------
//	Execute Read Firmware Update command (y0 F3 <P1P2=Block number> 00 Le Le)
//	Send command APDU receive response APDU, check returned SW1 SW2 code.
//-------------------------------------------------------------------------------
int V2X_ReadFirmware(int     userid,     // In: Admin/User ID
                     int     blocknr,    // In: NVM page number
                     BYTE    *data,      // Out: where to return data
                     int     len)        // In: data length to read
{
    BUILD_APDU_START(0xF3)
    BUILD_APDU_INDEX(blocknr)
    APDUbuffer[4] = 0x00;       // Extended Lc
    APDUbuffer[5] = (BYTE)(len >> 8);   // Extended Le
    APDUbuffer[6] = (BYTE)(len & 0xFF); // Extended Le

    if (V2X_send_apdu(userid, APDUbuffer, 7, RESP_APDU, &RESP_APDU_size, 20) &&
        RESP_APDU[RESP_APDU_size-2] == 0x90 && RESP_APDU[RESP_APDU_size-1] == 0x00)
    {
        RESP_APDU_size -= 2;
        if (data) memmove(data, RESP_APDU, RESP_APDU_size);
        return RESP_APDU_size;
    }
    return 0;
}

//-------------------------------------------------------------------------------
//   Calculate Key Check Value (KCV) using SHA256
//-------------------------------------------------------------------------------
void Calc_KCV_SHA(BYTE *keydata, int keysize, BYTE *kcv, int kcvlen)
{
    BYTE kcvbuf[32];
    if (kcv) memset(kcv, 0, kcvlen);
    if (keysize == 0) return;
    Crypto_Hash(keydata, keysize, kcvbuf, DIGEST_SIZE); // SHA256 over key value
    if (kcv) memcpy(kcv, kcvbuf, kcvlen);
}

//-------------------------------------------------------------------------------
//	Derive symmetric (AES256) encryption key from provided password
//-------------------------------------------------------------------------------
int DeriveKeyFromPassword(BYTE   *password,   // In: encryption password
                          int     passwordlen,// In: password length
                          int     keysize,    // In: required key length
                          BYTE   *key)        // Out: where to return data
{
    BYTE bIVkey[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
volatile BYTE keybuf[EVP_MAX_KEY_LENGTH];
    BYTE salt[8] = "v2x-hsm";
    int len;

    if (password == NULL || passwordlen == 0 || keysize == 0 || key == NULL) {
#ifdef DEBUG
        LogError("ERROR: DeriveKeyFromPassword: wrong parameters!\n");
#endif
        return 0;
    }
    // Derivation method: D_i = HASH^count(D_(i-1) || data || salt)
    // Where HASH^1(data) = HASH(data), HASH^2(data) = HASH(HASH(data)), ...
    len = EVP_BytesToKey(EVP_aes_256_cbc(), // AES256
                         EVP_sha256(),      // SHA256
                         salt,              // salt
                         password,          // input password
                         passwordlen,       // password length
                         10,                // Counter = 10 times
                         (BYTE*)keybuf,     // output key
                         bIVkey);           // IV
    if (len <= 0) {
#ifdef DEBUG
        LogError("ERROR: DeriveKeyFromPassword: EVP_BytesToKey failed!\n");
#endif
        return 0;
    }
    memcpy(key, (void*)keybuf, keysize);
    memset((void*)keybuf, 0, sizeof(keybuf)); // Clear key buffer
    return 1;
}
//-------------------------------------------------------------------------------
//	Encrypt (password-based encryption) and save data to a file on the host drive
//-------------------------------------------------------------------------------
int V2X_SaveToHostFile(char   *filename,   // In: key file name
                       BYTE   *password,   // In: encryption password
                       int     passwordlen,// In: password length
                       BYTE   *filedata,   // In: pointer to the file data
                       int     filesize)   // In: size of the data to write
{
volatile BYTE encrkey[AES256_KEY_SIZE];
    BYTE *outdata, *indata;
    int   insize = filesize + 16,
          outsize = filesize + 32,
          ret = 0;

    if (!DeriveKeyFromPassword(password, passwordlen, AES256_KEY_SIZE, (BYTE*)encrkey)) return 0;

    SAFE_MALLOC(indata, insize);
    SAFE_MALLOC(outdata, outsize);
    memcpy(indata, filedata, filesize); // copyinput data for padding

    Crypto_Encrypt((BYTE*)encrkey,     // Use AES key to decrypt the file
                    AES256_KEY_SIZE,   // key size - 32 bytes
                    ALG_AES_256,       // algorithm - AES256
                    CRYPT_MODE_CBC,    // CBC mode
                    indata,            // pointer to plain data
     ISO_padding_16(indata, filesize), // size of plain data
                    outdata,           // Encrypted data will be here
                    &outsize);         // size of encrypted data will be returned here

    if (!SaveToFile(filename, outdata, outsize)) {
        LogError("\nERROR: File '%s' writing error\n\n", filename);
        goto savefile_exit;
    }
    ret = 1;
savefile_exit:
    memset((void*)encrkey, 0, sizeof(encrkey)); // Clear key
    SAFE_FREE(outdata)
    SAFE_FREE(indata)
    return ret;
}

//-------------------------------------------------------------------------------
//	Load and decrypt file stored on the host drive (password-based encryption)
//-------------------------------------------------------------------------------
int V2X_LoadFromHostFile(char   *filename,   // In: key file name
                         BYTE   *password,   // In: encryption password
                         int     passwordlen,// In: password length
                         BYTE   *filedata,   // Out: decrypted file data will be copied here
                         int    *datalen)    // Out: actual file size, initially contains max file size
{
	volatile BYTE encrkey[AES256_KEY_SIZE] = { 0x00 };
    BYTE *outdata = NULL, *indata = NULL;
    int   filesize, decrsize, ret = 0;

    if (datalen) *datalen = 0;
    if (!DeriveKeyFromPassword(password, passwordlen, AES256_KEY_SIZE, (BYTE*)encrkey)) return 0;

    if (!(indata = LoadFromFile(filename, NULL, &filesize))) goto loadfile_exit;
    if (filesize == 0) { LogError("\nERROR: File '%s' is empty\n\n", filename); goto loadfile_exit; }

    SAFE_MALLOC(outdata, filesize);

    Crypto_Decrypt((BYTE*)encrkey,  // Use AES key to decrypt the file
                    AES256_KEY_SIZE,    // key size - 32 bytes
                    ALG_AES_256,        // algorithm - AES256
                    CRYPT_MODE_CBC,     // CBC mode
                    indata,             // pointer to encrypted data
                    filesize,           // size of encrypted data
                    outdata,           // Plain data will be returned here
                    &decrsize);         // size of decrypted data will be returned here
    decrsize = Remove_ISO_padding(outdata, decrsize);
    if (filedata) memcpy(filedata, outdata, decrsize);
    if (datalen) *datalen = decrsize;
    ret = 1;
loadfile_exit:
    memset((void*)encrkey, 0, sizeof(encrkey)); // Clear key
	if (outdata)
		SAFE_FREE(outdata)
	if (indata)
    SAFE_FREE(indata)
    return ret;
}

//-------------------------------------------------------------------------------
//	Load and decrypt the key from a file referenced by keyID stored on the host.
//  File name format: XXXXXXXX.key where XXXXXXXX is a keyID in hex format
//-------------------------------------------------------------------------------
int V2X_LoadUserKey(BYTE *keyid,            // In: pointer to KeyID (4 bytes)
                    char *util_password,    // In: password used to decrypt the key file
                    BYTE *userkey,          // Out: key will be copied here
                    int  *userkeysize)      // Out: key size will be copied here
{
    char filename[MAX_PATH+1];
    BYTE kcv[KEYIDSIZE];
    int  keysize = USER_KEY_SIZE; // Max buffer size for the key

    if (keyid == NULL || util_password == NULL || userkey == NULL) 
        { LogError("\nERROR: V2X_LoadUserKey: Invalid parameter(s)\n\n"); return 0; }

    if (memcmp(keyid, ZeroID, KEYIDSIZE) != 0) {
        if (userkeysize) *userkeysize = 0;
        sprintf(filename, "%s%02X%02X%02X%02X.key", KEYS_DIR, keyid[0], keyid[1], keyid[2], keyid[3]);
        if (!V2X_LoadFromHostFile(filename, util_password, strlen(util_password), userkey, &keysize)) return 0;

        Calc_KCV_SHA(userkey, keysize, kcv, KEYIDSIZE); // KCV of the key is the Key ID
        if (memcmp(keyid, kcv, KEYIDSIZE) != 0) { LogError("\nERROR: Invalid key file '%s'\n\n", filename); return 0; }
        if (userkeysize) *userkeysize = keysize;
    }
    return 1;
}

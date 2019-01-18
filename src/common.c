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

#include "common.h"

/*******************************
*    Variable Definitions      *
*******************************/

int LogLevel = 1;
	// Screen log verbose level:
	//-------------------------------
	// 0 - no screen log
	// 1 - minimum screen log
	// 2 - APDUs and responses shown on screen
	// 3 - deep SPI protocol debugging, all debug messages shown on screen

int LogLevelFile = 0; // File log verbose level - same as screen log


char LogFileName[PATH_MAX+1] = {LOG_FILENAME};

/*******************************
*    Function Definitions      *
*******************************/

int _kbhit(void)
{
  struct termios oldt, newt;
  int ch;
  int oldf;

  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

  ch = getchar();

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  fcntl(STDIN_FILENO, F_SETFL, oldf);

  if(ch != EOF)
  {
    ungetc(ch, stdin);
    return 1;
  }

  return 0;
}

int _getch(void)
{
    struct termios oldattr, newattr;
    int ch;
    tcgetattr( STDIN_FILENO, &oldattr );
    newattr = oldattr;
    newattr.c_lflag &= ~( ICANON | ECHO );
    tcsetattr( STDIN_FILENO, TCSANOW, &newattr );
    ch = getchar();
    tcsetattr( STDIN_FILENO, TCSANOW, &oldattr );
    return ch;
}

void Sleep(int time)
{
    usleep(time * 1000);
}

//--------------------------------------------------------------------
// Clear console screen.
//--------------------------------------------------------------------
void clrscr(void)
{
	system ("clear");
}

//--------------------------------------------------------------------
// XOR 2 byte arrays. Result is in pbOutBuffer.
//--------------------------------------------------------------------
void Xor (BYTE*  pbInBuffer, BYTE*  pbOutBuffer, uint32_t InputDataLen)
{
    int i;
    for (i=0; i < (int)InputDataLen; i++)
        pbOutBuffer[i] ^= pbInBuffer[i];
}

//--------------------------------------------------------------------
// Convert integer into a big endian 4 bytes array
//--------------------------------------------------------------------
void Big_Endian(int x, BYTE *arr)
{
    arr[0] = (BYTE) (x >> 24);
    arr[1] = (BYTE) ((x >> 16) & 0xFF);
    arr[2] = (BYTE) ((x >> 8)  & 0xFF);
    arr[3] = (BYTE) (x & 0xFF);
}

//--------------------------------------------------------------------
// String dump data to screen (in debug mode) and/or log file (if open)
// 1 - message
// 2 - parameter: pointer to dumped data
// 3 - parameter: dumped data length
//--------------------------------------------------------------------
void StrDump(char * message, BYTE *data, int len)
{
    char str[200] = { 0 };
    int slen;

    if (message && strlen(message) > 0) {
        strncpy(str, message, sizeof(str)-1);
    }
    slen = (int)strlen(str);
    if (data && len) {
        strncat(str + slen, (char*)data, sizeof(str) - slen - 1);
        str[slen + len] = 0;
    }
    Log("%s", str);
}

//--------------------------------------------------------------------
// Hex dump data to screen (in debug mode) and/or log file (if open)
// (without address)
// 1 - message
// 2 - parameter: pointer to dumped data
// 3 - parameter: dumped data length
//--------------------------------------------------------------------
void HexDump(char * message, BYTE *data, int len)
{
	int i, j, slen;
    char str[200] = { 0 };

    if (message && strlen(message) > 0) {
        strncpy(str, message, sizeof(str)-(16*3)-3);
    }
    slen = (int)strlen(str);

	for (i=0; i < len; i++, data++) {
		if ((i % 16) == 0 && i != 0) {
            Log("%s\n", str);
        	for (j=0; j < slen; j++) str[j] = ' ';  // Add spaces in front of 2... lines
            str[j] = 0;
        }
		sprintf(str + slen + (i % 16) * 3, "%.2X ", *data);
	}
	Log("%s\n", str);
}

//-----------------------------------------------------
void HexDumpPort(char * message, BYTE *data, int len)
{
	int saveLogLevelFile = LogLevelFile;
	int saveLogLevel = LogLevel;
	if (LogLevel < 2)  LogLevel = 0;
	if (LogLevelFile < 2) LogLevelFile = 0;
	if (LogLevel || LogLevelFile) HexDump(message, data, len);
	LogLevelFile = saveLogLevelFile;
	LogLevel = saveLogLevel;
}

//--------------------------------------------------------------------
// Build hex data string
//--------------------------------------------------------------------
char *HexStringNoSpace(BYTE *data, int num, char *dest)
{
static char strtmp[1000];
int i;
	if (data == NULL || num == 0) return "";
    if (dest == NULL) dest = strtmp;
    sprintf(dest, "%02X", data[0]);
    for (i = 1; i < num; i++)
        sprintf(dest + strlen(dest), "%02X", data[i]);
    return dest;
}

//--------------------------------------------------------------------
// Check if any key is pressed.
// Returns pressed key code in upper case.
//--------------------------------------------------------------------
short getKey(void)
{
    char c;
    c = _getch();

    if ((c & 0xFF) != 0xE0)
    {
        return toupper(c);
    }     // Check if it is an extended key
    return (0xE0 << 8 | toupper(_getch()));

}

//--------------------------------------------------------------------
// Check if any key is pressed.
// Returns pressed key code in upper case.
//--------------------------------------------------------------------
short checkKey(void)
{
    if (_kbhit()) return getKey();
    else return 0;
}

//--------------------------------------------------------------------
// Calculates a 16-bit CRC
//--------------------------------------------------------------------
short CalcCRC16(unsigned char *data, int len)
{
	unsigned short crc = 0x0000;
	unsigned char c;
    int i, j;

	for (i=0; i < len; i++)
	{
		c = data[i];
		crc ^= ((short)c);
		for (j=0; j<8; j++)
		{
			if (crc & 0x0001) crc = (crc >> 1) ^ 0x8408;
			else              crc = (crc >> 1);
		}
	}
	return crc;
}

//--------------------------------------------------------------------
// Get high resolution counter/timer in miliseconds
// Uses high-resolution performance counter if it is available on the system
//--------------------------------------------------------------------

LONGLONG GetTimerValue(void)
{
    LONGLONG msec, usec;
    struct timeval ts;
    gettimeofday(&ts,0);
    usec = (uint64_t)(ts.tv_sec * 1000000 + ts.tv_usec);
    msec = usec/1000;
    return msec;
}

//--------------------------------------------------------------------
// Convert hex string to byte array.
// Returns converted array length.
//--------------------------------------------------------------------
int UTIL_hexStrToArray(char *str, BYTE *res, int maxsize)
{
    int numbytes = 0, hexstart = 0, hexlen;
//  char seps[] = " ,.<>/?'\"!@#$%^&*()-_+=|\\:;\n\r\t{}";
    char seps[]    = " .<>/'\"-_\\:;\t";
    char hexvalid[] = "0x123456789ABCDEFabcdef";
    char hex[3];
    BYTE tmp[8];   // sscanf saves 4 bytes instead of 1

    if (str == NULL || strlen(str) == 0) return 0;
    if (res == NULL) return 0;

    res[0] = '\0';
    while(1) {
        hexstart += (int)strspn(str + hexstart, seps);

        if (strlen(str + hexstart) > 2 && str[hexstart] == '0' && (str[hexstart + 1] == 'x' || str[hexstart + 1] == 'X') ) 
            hexstart += 2;                        // Check if hex value is in "0xAA" format and skip 0x

        if ((hexlen = (int)strspn(str + hexstart, hexvalid)) == 0) return numbytes;

        if (hexlen > 2) { hex[0] = str[hexstart]; hex[1] = str[hexstart + 1]; hex[2] = 0; hexstart += 2; }
        else            { strncpy (hex, str + hexstart, hexlen);         hex[hexlen] = 0; hexstart += hexlen; }

        if (sscanf(hex, "%x", (unsigned int *)tmp) > 0) res[numbytes++] = tmp[0];
        else return 0;
        if (numbytes >= maxsize) return numbytes;
    }
}

//--------------------------------------------------------------------
// Return TRUE if file exists
//--------------------------------------------------------------------
int FileExists(char * filename)
{
    struct stat stat_buf;
    return (stat(filename, &stat_buf ) == 0) ? TRUE : FALSE;
}

//--------------------------------------------------------------------
// Write formatted to console and/or to the file LogFileName
// Log verbose level:
// - LogLevel - defines screen/console output messages level
// - LogLevelFile - defines log file output messages level
//---------------------------
// 0 - disable any screen/file messages,
// 1 - enable LogScreen() and LogError() messages on screen/file
// 2 - enable Log() - enable APDU dump + some debug messages on screen/file
// 3 - enable LogAll() - enable deep debugging messages on screen/file
//--------------------------------------------------------------------
int AddStringToLog(int level, char *pstr)
{
static BYTE firstTime = 0;
    char *openmode = "a+";
    FILE *stream;
    int ret = 1;

    if (LogLevel != 0 && level <= LogLevel) printf(pstr);    // Screen/console output

    if (LogLevelFile == 0 || LogFileName[0] == '0') return 1;// No file name set - file log disabled

    if (!firstTime) {                               // To minimize FileExists calls
        if (!FileExists(LogFileName)) openmode = "w+"; // Workaround for an "a+" bug in Windows
        firstTime = 1;                              //  use w+ only first time
    }
    if ((stream = fopen(LogFileName, openmode)) == NULL) {
        printf("System: appendFile error: Can't open file '%s'\n\n", LogFileName);
        return 0;
    }
    if (fprintf(stream, pstr) < 0) {
        printf("System: appendFile error: Can't write file '%s'\n\n", LogFileName);
        ret = 0;
    }
    fclose(stream);
    return ret;
}

//--------------------------------------------------------------------
// Console screen output and/or file logging
//--------------------------------------------------------------------
int LogScreen(char *format, ...)
{
    va_list arglist;
	char buffer[2000] = { 0x00 };

    if (LogLevel == 0 && LogLevelFile == 0) return 1; // Screen messages and file logging disabled

    va_start(arglist, format);
    vsnprintf(buffer, sizeof(buffer)-1, format, arglist);
    va_end(arglist);
	buffer[sizeof(buffer)-1] = 0;

    return AddStringToLog(0, buffer);
}

//--------------------------------------------------------------------
// Debug logging to console screen and/or file (APDU + some debug messages)
//--------------------------------------------------------------------
int Log(char *format, ...)
{
    va_list arglist;
	char buffer[2000];

    if (LogLevel == 0 && LogLevelFile == 0) return 1; // Screen messages and file logging disabled

    va_start(arglist, format);
    vsnprintf(buffer, sizeof(buffer)-1, format, arglist);
    va_end(arglist);
    buffer[sizeof(buffer)-1] = 0;

    return AddStringToLog(1, buffer);
}

//--------------------------------------------------------------------
// Debug logging to console screen and/or file (APDU + some debug messages)
//--------------------------------------------------------------------
int LogPort(char *format, ...)
{
    va_list arglist;
	char buffer[2000];

    if (LogLevel == 0 && LogLevelFile == 0) return 1; // Screen messages and file logging disabled

    va_start(arglist, format);
    vsnprintf(buffer, sizeof(buffer)-1, format, arglist);
    va_end(arglist);
    buffer[sizeof(buffer)-1] = 0;

    return AddStringToLog(2, buffer);
}

//--------------------------------------------------------------------
// Console screen output and/or file logging
//--------------------------------------------------------------------
int LogAll(char *format, ...)
{
    va_list arglist;
	char buffer[2000];

    if (LogLevel == 0 && LogLevelFile == 0) return 1; // Screen messages and file logging disabled

    va_start(arglist, format);
    vsnprintf(buffer, sizeof(buffer)-1, format, arglist);
    va_end(arglist);
    buffer[sizeof(buffer)-1] = 0;

    return AddStringToLog(3, buffer);
}

//-------------------------------------------------------------------------------
void DumpLine(int loglevel, int addr, BYTE *hexdata, int len)
{
    if (loglevel > 2) { // Dump hex file content if deep Debug log enabled
        Log("%08X:   ", addr);
        HexDump("", hexdata, len);
//      Log("\n");
    }
    else if (loglevel > 1) LogScreen("%08X  ", addr);
//  else if (loglevel > 0) LogScreen("\r%08X  ", addr);
}

//--------------------------------------------------------------------
// Open text file for reading
//--------------------------------------------------------------------
FILE *openFile(char *filename)
{
   char *openmode = "r+";
   FILE *stream = NULL;

   if (filename == NULL || strlen(filename) == 0) {
       LogError("System: openFile error: File name not specified\n\n");
       return NULL;
   }

   if ((stream = fopen(filename, openmode)) == NULL)
        LogError("System: openFile error: Can't open file '%s'\n\n", filename);

   return stream;
}

//--------------------------------------------------------------------
// Read a line from text file
//--------------------------------------------------------------------
int readLineFromFile(FILE *stream, char *data, int maxlen)
{
    if (fgets(data, maxlen, stream) == 0) {       // Read a line from text file
        if (ferror(stream))
            { LogError("System: Error reading file\n");  return 0; }
        return 0;
    }
    return (int)strlen(data);
}

//--------------------------------------------------------------------
// Close file
//--------------------------------------------------------------------
void closeFile(FILE *stream)
{
	if (stream) fclose(stream);
}

//--------------------------------------------------------------------
// LoadFromFile
//
// Description:
// Reads the contents of a File into the supplied Buffer
//
// Arguments:
//	len - must contain the buffer size
//
// Return Value:
//	Return			         Meaning
//	======			         =======
//	Pointer to a buffer		operation completed successfully.
//	NULL                    	operation failed.
//--------------------------------------------------------------------
BYTE* LoadFromFile(char *fname, BYTE *data, int *len)
{
    FILE *stream;
    int readbytes = 0;
    struct _stat sbuf;
    BYTE *pFileBuffer = data;
    unsigned long ulFileLength = 0L;

    if (_access(fname, 4) != 0) {   // get permissions
        LogError("System: LoadFromFile: Can't open file %s\n", fname);
        return NULL;
    }
    if (_stat(fname, &sbuf) == 0)   // get length of file
        ulFileLength = sbuf.st_size;
    else {
        LogError("System: LoadFromFile: Can't get file length: %s\n", fname);
        return NULL;
    }
    if (ulFileLength == 0) {
        LogError("System: LoadFromFile: File '%s' has zero length\n", fname);
        return NULL;
    }
    if (data) {                     // Buffer allocated by the caller
        if (len == NULL || *len == 0) {
            LogError("System: LoadFromFile: Buffer size is zero\n");
            return NULL;
        }
        if (*len < (int)ulFileLength){
            LogError("System: LoadFromFile: Buffer size (%d) is not enough for '%s' file (%d)\n",
                                                        *len, fname, (int)ulFileLength);
            return NULL;
        }
    }
    else {                          // Automatic buffer allocation
        if ((pFileBuffer = (BYTE *)malloc(ulFileLength)) == NULL) {
            LogError("System: LoadFromFile: Can't allocate memory (%d bytes)\n", (int)ulFileLength);
            return NULL;
        }
    }
    if ((stream = fopen( fname, "rb" )) != NULL)
    {
        readbytes = (int)fread( pFileBuffer, (size_t) 1, (size_t)ulFileLength, stream );
        fclose( stream );
        *len = readbytes;
        return pFileBuffer;
    }
    LogError("System: LoadFromFile: Can't open file %s\n\n", fname);
    return NULL;
}

//--------------------------------------------------------------------
// CompareBuffers - Compares 2 memory buffers with length len
//  Return Value:
//	RES_OK		buffers are identical
//	RES_ERROR	buffers are different
//--------------------------------------------------------------------
int CompareBuffers(BYTE *buf1, BYTE *buf2, int len1, int len2)
{
    int flag = 0, i, result = RES_OK;
    int len = (len1 > len2) ? len2 : len1;

    if (len1 != len2) {
        LogScreen("Wrong data size: %d. Should be %d\n", len2, len1);
        result = RES_ERROR;
    }
    for (i=0; i < len; i++)
        if (buf1[i] != buf2[i]) {
            if (flag == 0) {
                LogScreen("Differences found:\n");
                result = RES_ERROR;
            }
            if (++flag >= 10) return RES_ERROR;
            LogScreen("  %04X (%5d):  %02X - %02X\n", i, i, buf1[i], buf2[i]);
        }
   return result;
}

//--------------------------------------------------------------------
// SaveToFile
//
// Description:
// Writes the contents of the supplied Buffer into a File
//
// Arguments:
//
// Return Value:
//	Return		Meaning
//	======		=======
//	1               operation completed successfully.
//	0               operation failed.
//--------------------------------------------------------------------
int SaveToFile(char *fname, BYTE *data, int len)
{
   FILE *stream;

   if((stream = fopen(fname, "wb")) != NULL)
   {
       fwrite(data, (size_t) 1, (size_t) len, stream);
       fclose(stream);
       return 1;
   }
   LogError("System: Can't create file %s\n\n", fname);
   return 0;
}

//--------------------------------------------------------------------
// LoadFromHexFile
//
// Description:
// Reads the contents of a Hex File "fname" into the supplied "data" buffer
//
//Arguments:
//	minadr and maxadr set address range to read
//
//Returns:
//	StartAdr - the lowest address of loaded data
//	len      - number of bytes read
//
// Return Value:
//	Return		Meaning
//	======		=======
//	RES_OK		operation completed successfully.
//	RES_ERROR	operation failed.
//--------------------------------------------------------------------
int LoadFromHexFile(char *fname, BYTE *buffer, int offset, int minadr, int maxadr, int *StartAdr, int *EndAdr)
{
    FILE *stream;
    int  MinAdr = maxadr, MaxAdr = 0, i, nline = 0;
    char line[1000];
    int  BytesNum, RecordType, RecordAdr, bt, csum, ExtAddr=0;
    BYTE warnflag1 = 1, warnflag2 = 1;

    *StartAdr = 0;
    *EndAdr = 0;
    if ((maxadr - minadr) <= 0)
        { LogError("ERROR: Invalid Minimal (%08X) or Maximal (%08X) address specified\n\n",
                           minadr, maxadr);  return RES_ERROR; }

    if((stream = fopen( fname, "r" )) == NULL)
    {
        LogError("ERROR: Can't open file %s\n\n", fname);
        return RES_ERROR;
    }
    memset((void*) (buffer + minadr - offset), 0, maxadr - minadr);        // Fill buffer with FF

    while(!feof(stream))
    {
        if (fgets(line, sizeof(line), stream) == 0) {       // Read a line from HEX file
            if (ferror(stream))
                { LogError("ERROR: Error reading HEX file %s (line %d)\n\n",
                                   fname, nline);  return RES_ERROR; }
            else break;
        }
        nline++;
        if (line[0] == ';') continue;       // Skip comments
        if (strlen(line) == 0) continue;    // Skip empty lines
        if (line[0] != ':')
            { LogError("ERROR: Invalid HEX file %s (no ':' symbol)\n\n",
                               fname, nline);  return RES_ERROR; }

        // Read BytesNumber, RecordAddress, RecordType
        if (sscanf(line + 1, "%02x%04x%02x", &BytesNum, &RecordAdr, &RecordType) < 3)
            { LogError("ERROR: Invalid HEX file: %s (line %d - BytesNum,RecordAdr or RecordType invalid)\n\n",
                               line, nline);  return RES_ERROR; }
        BytesNum   &= 0xFF;
        RecordAdr  &= 0xFFFF;
        RecordType &= 0xFF;
        csum = BytesNum + (RecordAdr >> 8) + (RecordAdr & 0xFF) + RecordType;
        RecordAdr  += ExtAddr;

        if (strlen(line) < (size_t)((BytesNum * 2) + 11))
            { LogError("ERROR: Invalid HEX file: %s (line %d is too short)\n\n",
                               line, nline);  return RES_ERROR; }

		if (RecordType == 0) {                  // Record type 0 means: data
            //if (LogLevel > 2) {
            //    Log("%08X:   ", RecordAdr);
            //    StrDump("", line + 9, BytesNum * 2);
            //    Log("\n");
            //}
            //else if (LogLevel > 1) LogScreen("%08X  ", RecordAdr);
            //else LogScreen("\r%08X  ", RecordAdr);

            for (i=0; i < BytesNum; i++, RecordAdr++) {
                // Read Data byte
                if (sscanf(line + 9 + i + i, "%02x", &bt) == 0)
                    { LogError("ERROR: Invalid HEX file: %s (line %d - invalid data)\n\n",
                                       line, nline);  return RES_ERROR; }

                if (RecordAdr < minadr) {
                    if (warnflag1) { warnflag1 = 0;
                        LogError("WARNING: %s contains data address %08X less than minimum %08X (line %d)\n",
                                       line, RecordAdr, minadr, nline); }
                }
                else if (RecordAdr > maxadr) {
                    if (warnflag2) { warnflag2 = 0;
                        LogError("WARNING: %s contains data address %08X bigger than maximum %08X (line %d)\n",
                                       line, RecordAdr, maxadr, nline); }
                }
                else {
                    if (buffer[RecordAdr-offset] != 0x00)
                        { LogError("ERROR: Invalid HEX file: %s (data overlap in line %d address %08X) %02X\n\n",
                                           line, nline, RecordAdr, buffer[RecordAdr-offset]);  return RES_ERROR; }
                    buffer[RecordAdr-offset] = (BYTE) bt;
                    if (RecordAdr > MaxAdr) MaxAdr = RecordAdr;
                    if (RecordAdr < MinAdr) MinAdr = RecordAdr;
                }
                csum += (BYTE) bt;
            }
            // Read Check Sum byte
            if (sscanf(line + 9 + BytesNum + BytesNum, "%02x", &bt) == 0)
              { LogError("ERROR: Invalid HEX file: %s (line %d - can't read check sum)\n\n",
                                 line, nline);  return RES_ERROR; }
            csum += (BYTE) bt;
            if ((csum & 0xFF) != 0)
                { LogError("ERROR: Invalid HEX file: %s (line %d - invalid check sum)\n\n",
                                 line, nline);  return RES_ERROR; }
		}
		else if (RecordType == 1) {                  // Record type 1: End Of File
            //*StartAdr = MinAdr;
        }
		else if (RecordType == 4) {                  // Record type 4: Extended Linear Address
            // Read segment/offset
            if (sscanf(line + 9, "%04x", &ExtAddr) == 0)
            { LogError("ERROR: Invalid HEX file: %s\n  (line %d: Invalid Record Type 4 - Extended Linear Address)\n\n",
                                   line, nline);  return RES_ERROR; }

            ExtAddr <<= 16;
        }
        else { LogError("ERROR: Invalid HEX file %s\n  Line %d: %s\n  Unsupported Record Type %02X - Extended Linear Address)\n\n",
                                   fname, nline, line, RecordType);  return RES_ERROR; }
    }
    fclose(stream);
    *StartAdr = MinAdr;
    *EndAdr = MaxAdr;
    LogScreen("\nMin.address: %08X, Max.address: %08X\n", MinAdr, MaxAdr);
    return RES_OK;
}

//--------------------------------------------------------------------
// Sets ASN.1 BER tag length
//--------------------------------------------------------------------
int PutBERlen(int len, BYTE *buf, int index)
{
	if (len<128)        buf[index++]=(BYTE)len;
    else if (len<256) { buf[index++]=(BYTE)0x81;  buf[index++]=(BYTE)len; }
	else              { buf[index++]=(BYTE)0x82;  buf[index++]=(BYTE)(len/256); buf[index++]=(BYTE)(len%256); }
	return index;
}

//--------------------------------------------------------------------
// Sets ASN.1 BER tag and length
//--------------------------------------------------------------------
void PutTagLen1(BYTE tag, int datalen, BYTE *buf, int *index)
{
   	buf[(*index)++] = tag;
    *index = PutBERlen(datalen, buf, *index);
}

//--------------------------------------------------------------------
// Sets ASN.1 BER tag + length + data
//--------------------------------------------------------------------
int PutBERtag(BYTE tag, BYTE *data, int datalen, BYTE *buf, int index)
{
   	buf[index++] = tag;
    index = PutBERlen(datalen, buf, index);
    memmove(buf+index, data, datalen);
	return index + datalen;
}

//--------------------------------------------------------------------
// Ask utility password which is used to derive file encryption AES256 key
//--------------------------------------------------------------------
int Ask_Password(char *prompt, char *password)
{
    char temp[10000];
    if (*password != 0) return 1; // password already entered, don't ask again
    do {
        temp[0] = 0;
        LogScreen(prompt);
        scanf("%s", temp);
        if (strlen(temp) == 0) return 0; // Nothing entered - exit
        if      (strlen(temp) < 8)  { LogScreen("ERROR: Password must be at least 8 characters!\n"); }
        else if (strlen(temp) > 32) { LogScreen("ERROR: Password must be no longer than %d characters!\n", 32); }
        else break;
    } while(1);
    strcpy(password, temp);
    return 1;
}

//--------------------------------------------------------------------
// Trim string
//--------------------------------------------------------------------
char* trim(char* str, char* end) {
	while (isspace(*str)) ++str;
	while (isspace(*--end));
	end[1] = '\0';
	return str;
}

//--------------------------------------------------------------------
// Fill comment into structure
//--------------------------------------------------------------------
void parse_keyval(char* str, char* end, command_structure* structure)
{
	// the comment delimiter
	char* sep = strstr(str, "#");
	if (!sep) {
		// no comment found -> until next line
		char* sep1 = strstr(str, "\n");
		strcpy(structure->command, trim(str, sep1));
		memset(structure->comment, '\x00', sizeof(structure->comment));
		return;
	}
	// comment found
	strcpy(structure->command, trim(str, sep));
	strcpy(structure->comment, trim(sep + 1, end));	// + length of sep -> 1
}

//--------------------------------------------------------------------
// Search for comment tag #
//--------------------------------------------------------------------
int parse_comments(char* buffer, command_structure* defs, int maxdefs)
{
	int count = 0;
	char* str = buffer, *end;
	while (count < maxdefs && (end = strchr(str, '\n'))) {
		parse_keyval(str, end, &defs[count++]);
		str = end + 1;
	}
	return count;

}

//--------------------------------------------------------------------
// Read in file, allocate memory (release must be done outside!)
//--------------------------------------------------------------------
int read_file(char* filename, char ** ptr)
{
	FILE* stream = NULL;

	// open file in text mode
	if ((stream = openFile(filename)) == NULL) {
		fprintf(stderr, "Failed to open file %s\n", filename);
		return 0;
	}

	struct stat s;
	if (fstat(fileno(stream), &s) != 0) {
		fprintf(stderr, "Failed to get file status of %s\n", filename);
		return 0;
	}

	// allocated here, released in main
	*ptr = (char *)malloc(s.st_size + 1);
	if (*ptr == NULL) {
		fprintf(stderr, "Could not allocate memory of size 0x%08x \n", (s.st_size + 1));
		return 0;
	}
	else
		memset(*ptr, '\x00', s.st_size + 1);

	// read in file ...
	fread(*ptr, 1, s.st_size, stream);

	closeFile(stream);
	return 1;
}

//--------------------------------------------------------------------
// Remove defined characters from string
//--------------------------------------------------------------------
char * stringRemoveChars(char *string, char *spanset) {
	char *ptr = string;
	ptr = strpbrk(ptr, spanset);

	while (ptr != NULL) {
		char * x = ptr++;
		(*x) = 0x00;
		strcat(x, ptr);
		ptr = strpbrk(x, spanset);
	}

	return string;
}

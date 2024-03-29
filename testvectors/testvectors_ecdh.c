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

// ECDH test vectors    -   NIST P-256 (prime256v1/secp256r1)
//-------------------------------------------------------------------------
// QCAVSx= 700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
// QCAVSy= db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
// dIUT  = 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
// QIUTx = ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230
// QIUTy = 28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
// ZIUT  = 46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b

// 04 700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287 db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
BYTE BYTE_TestVectorPubKeyECC256_Host[] = {
    0x04,
    0x70,0x0c,0x48,0xf7,0x7f,0x56,0x58,0x4c,0x5c,0xc6,0x32,0xca,0x65,0x64,0x0d,0xb9,0x1b,0x6b,0xac,0xce,0x3a,0x4d,0xf6,0xb4,0x2c,0xe7,0xcc,0x83,0x88,0x33,0xd2,0x87,
    0xdb,0x71,0xe5,0x09,0xe3,0xfd,0x9b,0x06,0x0d,0xdb,0x20,0xba,0x5c,0x51,0xdc,0xc5,0x94,0x8d,0x46,0xfb,0xf6,0x40,0xdf,0xe0,0x44,0x17,0x82,0xca,0xb8,0x5f,0xa4,0xac};
ECPublicKey ECPubK_TestVectorECC256_Host = { 0x41, BYTE_TestVectorPubKeyECC256_Host };

// 04 ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230 28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
BYTE BYTE_TestVectorPubKeyECC256_Chip[] = {
    0x04,
    0xea,0xd2,0x18,0x59,0x01,0x19,0xe8,0x87,0x6b,0x29,0x14,0x6f,0xf8,0x9c,0xa6,0x17,0x70,0xc4,0xed,0xbb,0xf9,0x7d,0x38,0xce,0x38,0x5e,0xd2,0x81,0xd8,0xa6,0xb2,0x30,
    0x28,0xaf,0x61,0x28,0x1f,0xd3,0x5e,0x2f,0xa7,0x00,0x25,0x23,0xac,0xc8,0x5a,0x42,0x9c,0xb0,0x6e,0xe6,0x64,0x83,0x25,0x38,0x9f,0x59,0xed,0xfc,0xe1,0x40,0x51,0x41};
ECPublicKey ECPubK_TestVectorECC256_Chip = { 0x41, BYTE_TestVectorPubKeyECC256_Chip };

BYTE BYTE_TestVectorPrivKeyECC256_Chip[] = {0x7d,0x7d,0xc5,0xf7,0x1e,0xb2,0x9d,0xda,0xf8,0x0d,0x62,0x14,0x63,0x2e,0xea,0xe0,0x3d,0x90,0x58,0xaf,0x1f,0xb6,0xd2,0x2e,0xd8,0x0b,0xad,0xb6,0x2b,0xc1,0xa5,0x34};
ECPrivateKey ECPrvK_TestVectorECC256_Chip= { 0x20, BYTE_TestVectorPrivKeyECC256_Chip };

//BYTE TestVectorECDH256[] = "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b";

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

// Test vectors for ECIES as per 1609.2 v3
// -----------------------------------------------------------------------------------------------------
// ECIES Encryption is used to wrap AES-CCM 128-bit keys
//
// Encryption Inputs:
// - R:  {ec256 point} Recipient public key
// - k:  {octet string} AES-CCM 128-bit key to be wrapped (128 bits)
// - P1: {octet string} SHA-256 hash of some defined recipient info or of an empty string (256 bits)
//
// Encryption Outputs:
// - V:  {ec256 point} Sender's ephemeral public key
// - C:  {octet string} Ciphertext, i.e. enc(k) (128 bits)
// - T:  {octet string} Authentication tag, (128 bits)
//
// The encryption output is randomised, due to the ephemeral sender's key (v,V)
// In the script, for testing purpose:
// - v is an optional input to ecies_enc()
// - v is an output of ecies_enc() to be printed in the test vectors
//
//Recipient key
// Rx = "8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11"
// Ry = "1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E"
// r  = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"
//Ephemeral key
// Vx = "F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828"
// Vy = "F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729"
// v  = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"
//Data=key
// k  = "9169155B08B07674CBADF75FB46A7B0D"
//Parameter
// P1 = "A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9"


// -----------------------------------------------------------------------------------------------------
//                       ECIES test vectors                     -           CAMP test vectors
// -----------------------------------------------------------------------------------------------------

// Recipient's public key:
char *TestVector_ECIES_R[] = {"04 8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11 1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E",
                              "04 8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11 1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E",
                              "04 8008B06FC4C9F9856048DA186E7DC390963D6A424E80B274FB75D12188D7D73F 2774FB9600F27D7B3BBB2F7FCD8D2C96D4619EF9B4692C6A7C5733B5BAC8B27D",
                              "04 8008B06FC4C9F9856048DA186E7DC390963D6A424E80B274FB75D12188D7D73F 2774FB9600F27D7B3BBB2F7FCD8D2C96D4619EF9B4692C6A7C5733B5BAC8B27D"
};
// Recipient's private key:
char *TestVector_ECIES_r[] = {"060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085",
                              "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085",
                              "DA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744",
                              "DA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744"
};
// Sender's ephemeral public key:
char *TestVector_ECIES_V[] = {"04 F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828 F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729",
                              "04 EE9CC7FBD9EDECEA41F7C8BD258E8D2E988E75BD069ADDCA1E5A38E534AC6818 5AE3C8D9FE0B1FC7438F29417C240F8BF81C358EC1A4D0C6E98D8EDBCC714017",
                              "04 F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828 F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729",
                              "04 121AA495C6B2C07A2B2DAEC36BD207D6620D7E6081050DF5DE3E9696868FCDCA 46C31A1ABEA0BDDAAAAEFBBA3AFDBFF1AC8D196BC313FC130926810C05503950"
};
// Sender's ephemeral private key:
char *TestVector_ECIES_v[] = {"1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42",
                              "D418760F0CB2DCB856BC3C7217AD3AA36DB6742AE1DB655A3D28DF88CBBF84E1",
                              "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42",
                              "4624A6F9F6BC6BD088A71ED97B3AEE983B5CC2F574F64E96A531D2464137049F"
};
// AES key to be encrypted (wrapped):
char *TestVector_ECIES_k[] = {"9169155B08B07674CBADF75FB46A7B0D",
                              "9169155B08B07674CBADF75FB46A7B0D",
                              "687E9757DEBFD87B0C267330C183C7B6",
                              "687E9757DEBFD87B0C267330C183C7B6"
};
// Hash(RecipientInfo):
char *TestVector_ECIES_P[] = {"A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9",
                              "A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9",
                              "05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051",
                              "05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051"
};
// Encrypted data
char *TestVector_ECIES_C[] = {"A6342013D623AD6C5F6882469673AE33",
                              "DD530BE3BCD149E881E09F06E160F5A0",
                              "1F6346EDAEAF57561FC9604FEBEFF44E",
                              "6CFD13B76436CD0DB70244FAE380CBA1"
};
// Tag
char *TestVector_ECIES_T[] = {"80e1d85d30f1bae4ecf1a534a89a0786",
                              "06c1f0f5eaed453caf78e01a3d16a001",
                              "373c0fa7c52a0798ec36eadfe387c3ef",
                              "c8bf18ac796b0b1d3a1256d3a91676c8"
};

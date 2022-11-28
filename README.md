# HiveV5 file decryptor PoC

## Introduction

The work done in the last few months has been necessary to reveal the malicious file encryption mechanism of Hive v5-5.2.
The work was divided into two parts
1. [Keystream decryption] (https://github.com/reecdeep/HiveV5_keystream_decryptor)
2. File decryption using the decrypted keystream

I would like to thank the great [@rivitna](https://twitter.com/rivitna2) for the support, dialogue and advice of these months of work!
Please take note of [rivitna's github](https://github.com/rivitna) full of useful information about Hive ransomware and more.

In this readme you will find some information about the file decryption algorithm, referring you to the PoC for a more complete picture of how it works.
A keystream is an encrypted cleartext. A cleartext is a set of 0xA00000 bytes to which the first 0x2FFF00 bytes have been appended, for a total of 0xCFFF00 bytes. These bytes were created with the weak algorithm already discussed in the first part released in July 2022.
Here below is a example of cleartext:
![cleartext](https://user-images.githubusercontent.com/72123074/204250635-f96b579f-c19b-4c14-be15-157300e1633d.png)


The Hive sample analyzed and referred to in this document was chosen from [this list](https://github.com/rivitna/Malware/blob/main/Hive/Hive_samples.txt) created by [@rivitna](https://twitter.com/rivitna2) to which my warmest thanks go.
To get an idea of the complexity of ransomware, please take a look at [this analysis](https://www.microsoft.com/security/blog/2022/07/05/hive-ransomware-gets-upgrades-in-rust/) published by Microsoft Threat Intelligence Center (MSTIC).


## File encryption algorithm

The cleartext (a decrypted keystream) is used by Hive ransomware when encrypting each file. When encrypting a file, Hive ransomware calculates two integers referring to precise positions in the cleartext (offsets) to be used to encrypt the file according to the following formula:

![formula](https://user-images.githubusercontent.com/72123074/204250645-788c1269-cbf8-4006-b042-b16ee7756cdb.png)

where c = i % 0x2FFF00 e d = i % 0x2FFD00 , with i  as a byte counter.



## The encrypted file extension
The preliminary operations before writing a file are:
- Renaming the file using MoveFileExW and changing its extension;
- Writing the renamed file with the result of the xor operation shown above.

![file_extension](https://user-images.githubusercontent.com/72123074/204250641-2567b7f9-cc42-4516-b378-b357eed4d018.png)

Also in this case the cleartext plays a fundamental role. In fact it is used for:
1. Determine the keystream ID (first 6 bytes) using a hash function
2. Encrypt the positions (offsets) used to extract bytes from the cleartext
However, the first offset is encrypted using a fixed position of the cleartext and is different for each Hive 5/5.1/5.2 sample.
A kind of magical value. In many Hive 5/5.1 artifacts this magic value is shown explicitly inside a memory reference, like in this case 0x98072A :

![off1](https://user-images.githubusercontent.com/72123074/204250648-da2d1514-2e56-4849-8090-79ad25625298.png)

Or this case 0x7539D:

![off2](https://user-images.githubusercontent.com/72123074/204250651-82ea5c5d-840f-486a-807a-1a7a62f30811.png)

But in the next evidence the for loop is slightly different and has been written in such a way as not to explicit the magic value that we need to identify. This concerns an artifact belonging to Hive 5.2:

![off3](https://user-images.githubusercontent.com/72123074/204250653-a747b1bb-e1d7-4061-a21c-d3c72612c93f.png)

In this case it is possible to use the offset bruteforce function present in the released tool, using a file with a known extension and the relative decrypted keystream. Using the header of the encrypted file and the header of the unencrypted file it is possible to understand what is the offset from which the decryptor must start to decrypt the file.

The file encryption mode can have two values: 0xFB or 0xFF
- 0xFB means that the ransomware encrypted the entire file without leaving any portion of the file unencrypted.
- 0xFF means that the ransomware calculated a NCB (not encrypted block) for each file and encrypting blocks of 0x100000 bytes.
For further information regarding the calculation of the size of the unencrypted blocks and the cleartext offset, please refer to the PoC code.


## Usage
The program offers two options:

![usage](https://user-images.githubusercontent.com/72123074/204250655-5e8c46e1-f9aa-4718-bcfe-ca60ff34b5b1.png)

1. Decryption of files using the decrypted keystream. You need to enter the special offset present in the sample that encrypted the files.
2. Given a file with a known header (PDF, JPG, PNG, Office files) brute the possible value of the special offset by decrypting the first bytes and looking for a match with the known signature


## References

<https://github.com/rivitna/Malware/blob/main/Hive/Hive_samples.txt>

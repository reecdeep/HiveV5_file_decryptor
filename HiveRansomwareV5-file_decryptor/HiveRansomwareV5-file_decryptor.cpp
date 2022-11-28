
#include <Windows.h> 
#include <shlwapi.h>
#include <iostream>
#include <stdio.h>
#include <fstream> 
#include <string>
#include <sstream>
#include <vector>
#include <iterator>
#include <iomanip>
#include <thread>
#include <set>
#include <string_view>
#include <functional>
#include <algorithm>
#include <string>
#include <filesystem>

#pragma comment(lib,"shlwapi.lib")

std::vector<BYTE> base64_decode(const std::string & in);
void openFile(std::string file_name, unsigned char* buffer, int dim);
void file_decrypt();
void offset_bruteforce();


//the working path will be updated when selecting files
std::string currentWorkingPath = "";

const char base64_url_alphabet[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

//array for storing decrypted keystream 
unsigned char* decrypted_keystream = new unsigned char[0xCFFF00]();
//size of NOT Cyphered Block
unsigned int ncb_size;

//this field changes, on each HIVE sample!
//unsigned int specialOffset = 0x2ABD4E;
//unsigned int specialOffset = 0x98072A;
unsigned int specialOffset = 0;

//flag NCB swicth /non crypted block)
boolean ncb_override = true;
unsigned char* knownheader;





int main()
{

	std::string j;

	std::cout << "Hive ransomware V5 - file decryptor PoC" << std::endl;
	std::cout << "--------------------------------------------\n" << std::endl;

	std::cout << "1. Decrypt a file using decrypted keystream" << std::endl;
	std::cout << "2. Offset bruteforce" << std::endl;
	std::cout << "your move: " << std::endl;

	j = std::cin.get();


		if (j == "1")
		{
			file_decrypt();
		}
		else
			if (j == "2")
			{
				offset_bruteforce();
			}


}





void file_decrypt()
{
	//open the decrypted keystream file
	std::cout << "Please enter the decrypted keystream file: \n";
	std::string path_decrypted_keystream;
	std::cin >> path_decrypted_keystream;
	path_decrypted_keystream.erase(remove(path_decrypted_keystream.begin(), path_decrypted_keystream.end(), '\"'), path_decrypted_keystream.end());
	std::ifstream ifs(path_decrypted_keystream.c_str());

	if (!ifs)
	{
		std::cout << "error opening keystream file!";
	}
	else
	{
		//ask for offset
		std::cout << "Please enter the offset value in hex format (0x12345678): \n";
		std::cin >> std::hex >> specialOffset;


		

		while (true)
		{
			//open the file to be decrypted
			std::cout << "Please enter the encrypted file: \n";
			std::string path_encrypted_file;
			std::cin >> path_encrypted_file;
			path_encrypted_file.erase(remove(path_encrypted_file.begin(), path_encrypted_file.end(), '\"'), path_encrypted_file.end());
			std::ifstream ifs(path_encrypted_file.c_str());

			//updating working path based on encrypted file position in file system
			currentWorkingPath = path_encrypted_file.substr(0, path_encrypted_file.find_last_of("/\\"));

			if (!ifs)
			{
				std::cout << "error opening encrypted file!\n";
			}
			else
			{
				//get encrypted file extension
				size_t i = path_encrypted_file.rfind('.', path_encrypted_file.length());
				if (i != std::string::npos)
				{
					std::string extension = (path_encrypted_file.substr(i + 1, path_encrypted_file.length() - i));
					std::vector<BYTE> decoded_extension = base64_decode(extension);
					//byte dimension of decoded byte
					int dim_decoded_extension = decoded_extension.size();

					//transform to array
					unsigned char* decoded_extension_array = new unsigned char[dim_decoded_extension]();
					std::copy(decoded_extension.begin(), decoded_extension.end(), decoded_extension_array);

					//read the decrypted keystream
					openFile(path_decrypted_keystream, decrypted_keystream, 0xCFFF00);

					//extract xor key from decrypted keystream
					unsigned char* first_offset_xor = new unsigned char[4]();
					memcpy(first_offset_xor, decrypted_keystream + specialOffset - 0x4, 4);

					//get first offset
					unsigned char* first_offset = new unsigned char[4]();
					memcpy(first_offset, decoded_extension_array + dim_decoded_extension - 8, 4);

					//read decryption mode byte
					unsigned char decryption_mode = decoded_extension_array[6];
					
					//case decryption mode is 0xFB
					if (decryption_mode == '0xFB')
					{
						//no crypted block mode
						ncb_override = true;
					}
					else
					{
						//case decryption mode is 0xFF
						//crypted block mode on!
						ncb_override = false;
					}



					//first offset xored
					unsigned char* first_offset_xored = new unsigned char[4]();

					//xor first offset with xor key extracted from decrypted keystream
					for (int i = 0; i < 4; i++)
					{
						first_offset_xored[i] = first_offset[i] ^ first_offset_xor[i];
					}

					//first offset xored to littleEndian
					unsigned char* first_offset_xored_le = new unsigned char[4]();
					first_offset_xored_le[0] = first_offset_xored[3];
					first_offset_xored_le[1] = first_offset_xored[2];
					first_offset_xored_le[2] = first_offset_xored[1];
					first_offset_xored_le[3] = first_offset_xored[0];

					//TO int
					unsigned int first_offset_xored_int = (first_offset_xored_le[0] << 24 |
						first_offset_xored_le[1] << 16 |
						first_offset_xored_le[2] << 8 |
						first_offset_xored_le[3]);

					//mul offset with fixed value 0x3333347B
					unsigned long long mul1 = (unsigned long long) first_offset_xored_int * 0x3333347B;

					//shifting to the right the upper part of the mul1 long long by 15
					unsigned int shift1 = (unsigned int)(mul1 >> 32) >> 0x15;

					//mul shift with fixed value 0x9FFFFC
					unsigned int mul2 = shift1 * 0x9FFFFC;

					//difference between offset1 and mul2 (acts like second offset xor key)
					unsigned int diff1 = first_offset_xored_int - mul2;

					//extract second xor key from decrypted keystream
					unsigned char* second_offset_xor = new unsigned char[4]();
					memcpy(second_offset_xor, decrypted_keystream + diff1, 4);

					//get second offset
					unsigned char* second_offset = new unsigned char[4]();
					memcpy(second_offset, decoded_extension_array + dim_decoded_extension - 4, 4);


					//second offset xored
					unsigned char* second_offset_xored = new unsigned char[4]();

					//xor second offset with second xor key extracted from decrypted keystream
					for (int i = 0; i < 4; i++)
					{
						second_offset_xored[i] = second_offset[i] ^ second_offset_xor[i];
					}

					//second offset xored to littleEndian
					unsigned char* second_offset_xored_le = new unsigned char[4]();
					second_offset_xored_le[0] = second_offset_xored[3];
					second_offset_xored_le[1] = second_offset_xored[2];
					second_offset_xored_le[2] = second_offset_xored[1];
					second_offset_xored_le[3] = second_offset_xored[0];

					//TO int
					unsigned int second_offset_xored_int = (second_offset_xored_le[0] << 24 |
						second_offset_xored_le[1] << 16 |
						second_offset_xored_le[2] << 8 |
						second_offset_xored_le[3]);


					//mul first_offset_xored_le with 0xCCCCCCCD
					unsigned long long mul3 = (unsigned long long) first_offset_xored_int * 0xCCCCCCCD;
					//mul second_offset_xored_le with 0xCCCCCCCD
					unsigned long long mul4 = (unsigned long long) second_offset_xored_int * 0xCCCCCCCD;

					//shifting to the right the upper part of the mul3 long long by 2
					unsigned int shift2 = (unsigned int)(mul3 >> 32) >> 0x2;

					//logic-AND between shift2 and 0x3FE00000
					unsigned int and1 = shift2 & 0x3FE00000;

					//mul and1 by 5 times
					unsigned int mul5 = and1 * 5;

					//REAL FIRST OFFSET FOR XOR KEY
					unsigned int real_first_XORKEY_offset = first_offset_xored_int - mul5;

					//shifting to the right the upper part of the mul4 long long by 2
					unsigned int shift3 = (unsigned int)(mul4 >> 32) >> 0x2;

					//logic-AND between shift3 and 0x3FE00000
					unsigned int and2 = shift3 & 0x3FE00000;

					//mul and1 by 5 times
					unsigned int mul6 = and2 * 5;

					//REAL SECOND OFFSET FOR XOR KEY
					unsigned int real_second_XORKEY_offset = second_offset_xored_int - mul6;

					//get encrypted file size
					std::ifstream in_file(path_encrypted_file.c_str(), std::ios::binary);
					in_file.seekg(0, std::ios::end);
					int file_size = in_file.tellg();

					//unsigned char* file_clear = new unsigned char[file_size]();
					//unsigned char* file_encrypted = new unsigned char[file_size]();

					unsigned char* file_clear;
					file_clear = (unsigned char*)malloc(file_size);

					unsigned char* file_encrypted;
					file_encrypted = (unsigned char*)malloc(file_size);

					//read the encrypted file
					openFile(path_encrypted_file, file_encrypted, file_size);


					//NCB-Not-cyphered-block size computation
					if (file_size > 0x100000)
					{

						//unsigned int file_size = 0x4c4b40;
						//unsigned int file_size = 0x100001;
						unsigned long long shl = (unsigned long long)file_size << 0xB;

						//get the high part of shl operation
						unsigned int shl_hp = shl >> 0x20;

						//off
						unsigned int edx = 0;

						if (0xC9FFFFF >= file_size)
						{
							edx = shl_hp;

						}
						else
						{
							edx = 0x64;
						}

						unsigned int shl3 = edx << 0x14;

						unsigned int sub1 = file_size - shl3;
						unsigned int sub2 = edx - 1;
						if (sub2 > 0)
						{
							ncb_size = sub1 / sub2;
						}
						else
						{
							ncb_size = sub1;
						}

					}





					//storing count of byte being decrypted
					//this variable is used to access in incremental way the decrypted keystream array
					//this variable is never reset
					unsigned int total_decrypted_count = 0;

					unsigned int total_decrypted_blocks = 0;

					//if the ncb_size is larger than 0, it means the file is not completely encrypted
					//so there are not cyphered blocks
					if (ncb_size > 0 && (ncb_override == false))
					{
						//counter of cyphering block, for resetting the cryptedBlock flag
						unsigned int decypher_count = 0;

						//counter of first offset
						unsigned int not_cyphered_count = 0;

						//flag to distinguish from encrypted block or not encrypted block
						boolean cryptedBlock = true;

						unsigned int mod_first_offset = 0;
						unsigned int mod_second_offset = 0;
						unsigned int total_decrypted_count = 0;

						for (int i = 0; i < file_size; i++)
						{
							mod_second_offset = total_decrypted_count % 0x2FFF00;
							mod_first_offset = total_decrypted_count % 0x2FFD00;

							//if I'm on a crypted block 
							if (cryptedBlock)
							{
								file_clear[i] = decrypted_keystream[real_first_XORKEY_offset + mod_second_offset] ^
									decrypted_keystream[real_second_XORKEY_offset + mod_first_offset] ^
									file_encrypted[i];

								decypher_count++;
								total_decrypted_count++;
							}
							else
							{
								file_clear[i] = file_encrypted[i];

								not_cyphered_count++;
							}


							//if cypher_count reaches the end of the encrypted block 
							if (decypher_count == 0x100000)
							{
								//update the decryption block count
								total_decrypted_blocks++;

								cryptedBlock = false;

								//reset the counter
								decypher_count = 0;
							}

							//if reach the count of ncb_size, then start deciphering again and set not cyphered_count to zero
							if (not_cyphered_count == ncb_size)
							{
								cryptedBlock = true;

								//reset the counter
								not_cyphered_count = 0;
							}


						}
					}
					else
					{
						unsigned int mod_first_offset = 0;
						unsigned int mod_second_offset = 0;

						for (int i = 0; i < file_size; i++)
						{
							mod_second_offset = i % 0x2FFF00;
							mod_first_offset = i % 0x2FFD00;

							file_clear[i] = decrypted_keystream[real_first_XORKEY_offset + mod_second_offset] ^
								decrypted_keystream[real_second_XORKEY_offset + mod_first_offset] ^
								file_encrypted[i];

						}




					}



					// Character to be found
					char ch = '.';

					// To store the index of last
					// character found
					size_t found;

					// Function to find the last
					// character ch in str
					found = path_encrypted_file.find_last_of(ch);

					std::string outputFile = path_encrypted_file.substr(0, found);

					std::ofstream outfile_keystream(outputFile, std::ofstream::binary);
					outfile_keystream.write((const char *)file_clear, file_size);
					outfile_keystream.close();




				}
				else
				{

				}




			



			}

		}




	}
}


std::vector<BYTE> base64_decode(const std::string & in)
{
	std::vector<BYTE> out;
	std::vector<int> T(256, -1);
	unsigned int i;
	for (i = 0; i < 64; i++) T[base64_url_alphabet[i]] = i;

	int val = 0, valb = -8;
	for (i = 0; i < in.length(); i++) {
		unsigned char c = in[i];
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(BYTE((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

void openFile(std::string file_name, unsigned char* buffer, int dim)
{

	// open the file:
	std::streampos fileSize;
	std::ifstream file(file_name, std::ios::binary);


	// read the data:
	//buffer = new unsigned char[dim]();
	file.read((char*)&buffer[0], dim);


}












void offset_bruteforce()
{
	//open the decrypted keystream file
	std::cout << "Please enter the decrypted keystream file: \n";
	std::string path_decrypted_keystream;
	std::cin >> path_decrypted_keystream;
	path_decrypted_keystream.erase(remove(path_decrypted_keystream.begin(), path_decrypted_keystream.end(), '\"'), path_decrypted_keystream.end());
	std::ifstream ifs(path_decrypted_keystream.c_str());

	if (!ifs)
	{
		std::cout << "error opening keystream file!";
	}
	else
	{

		int headerLen = 0;

		std::cout << "Please enter the int referring to the extension (0:pdf, 1:doc|xls|ppt, 2:jpg, 3:png, 4:docx|xlsx|pptx ): \n";
		int choosen_extension;
		std::cin >> choosen_extension;

		switch (choosen_extension)
		{
		case 0:
			printf("you choosed pdf\n");
			headerLen = 5;
			knownheader = new unsigned char[headerLen]();
			knownheader[0] = 0x25;
			knownheader[1] = 0x50;
			knownheader[2] = 0x44;
			knownheader[3] = 0x46;
			knownheader[4] = 0x2D;
	
			break; 
		case 1:
			
			printf("you choosed doc|xls|ppt\n");
			headerLen = 8;
			knownheader = new unsigned char[headerLen]();
			knownheader[0] = 0xD0;
			knownheader[1] = 0xCF;
			knownheader[2] = 0x11;
			knownheader[3] = 0xE0;
			knownheader[4] = 0xA1;
			knownheader[5] = 0xB1;
			knownheader[6] = 0x1A;
			knownheader[7] = 0xE1;

			break;
		case 2:
			printf("you choosed jpg\n");
			headerLen = 3;
			knownheader = new unsigned char[headerLen]();
			knownheader[0] = 0xFF;
			knownheader[1] = 0xD8;
			knownheader[2] = 0xFF;
			break;
		case 3:
			printf("you choosed png\n");
			headerLen = 8;
			knownheader = new unsigned char[headerLen]();
			knownheader[0] = 0x89;
			knownheader[1] = 0x50;
			knownheader[2] = 0x4E;
			knownheader[3] = 0x47;
			knownheader[4] = 0x0D;
			knownheader[5] = 0x0A;
			knownheader[6] = 0x1A;
			knownheader[7] = 0x0A;
			break;
		case 4:
			printf("you choosed docx|xlsx|pptx\n");
			headerLen = 4;
			knownheader = new unsigned char[headerLen]();
			knownheader[0] = 0x50;
			knownheader[1] = 0x4B;
			knownheader[2] = 0x03;
			knownheader[3] = 0x04;
			break;


		default:
			printf("Wrong choose!\n");
			break;
		}


		//open the file to be decrypted
		std::cout << "Please enter the encrypted file with the same extension: \n";
		std::string path_encrypted_file;
		std::cin >> path_encrypted_file;
		path_encrypted_file.erase(remove(path_encrypted_file.begin(), path_encrypted_file.end(), '\"'), path_encrypted_file.end());
		std::ifstream ifs(path_encrypted_file.c_str());

		//updating working path based on encrypted file position in file system
		currentWorkingPath = path_encrypted_file.substr(0, path_encrypted_file.find_last_of("/\\"));

		if (!ifs)
		{
			std::cout << "error opening encrypted file!";
		}
		else
		{
			//get encrypted file extension
			size_t i = path_encrypted_file.rfind('.', path_encrypted_file.length());
			if (i != std::string::npos)
			{
				std::string extension = (path_encrypted_file.substr(i + 1, path_encrypted_file.length() - i));
				std::vector<BYTE> decoded_extension = base64_decode(extension);
				//byte dimension of decoded byte
				int dim_decoded_extension = decoded_extension.size();

				//transform to array
				unsigned char* decoded_extension_array = new unsigned char[dim_decoded_extension]();
				std::copy(decoded_extension.begin(), decoded_extension.end(), decoded_extension_array);

				//read the decrypted keystream
				openFile(path_decrypted_keystream, decrypted_keystream, 0xCFFF00);

				//extract xor key from decrypted keystream
				unsigned char* first_offset_xor = new unsigned char[4]();

				boolean isOffsetNotFound = true;
				//special offset from zero until I find the right offset
				specialOffset = 0;

				std::cout << "Starting offset bruteforce from " << specialOffset << " \n";

				//crea vettore per file cifrato
				unsigned char* file_encrypted = new unsigned char[4]();
				//leggi i primi [lunghezzaHeader] byte del file cifrato
				openFile(path_encrypted_file, file_encrypted, headerLen);

				while (isOffsetNotFound)
				{
					memcpy(first_offset_xor, decrypted_keystream + specialOffset - 0x4, 4);
					//get first offset
					unsigned char* first_offset = new unsigned char[4]();
					memcpy(first_offset, decoded_extension_array + dim_decoded_extension - 8, 4);

					//first offset xored
					unsigned char* first_offset_xored = new unsigned char[4]();

					//xor first offset with xor key extracted from decrypted keystream
					for (int i = 0; i < 4; i++)
					{
						first_offset_xored[i] = first_offset[i] ^ first_offset_xor[i];
					}

					//first offset xored to littleEndian
					unsigned char* first_offset_xored_le = new unsigned char[4]();
					first_offset_xored_le[0] = first_offset_xored[3];
					first_offset_xored_le[1] = first_offset_xored[2];
					first_offset_xored_le[2] = first_offset_xored[1];
					first_offset_xored_le[3] = first_offset_xored[0];

					//TO int
					unsigned int first_offset_xored_int = (first_offset_xored_le[0] << 24 |
						first_offset_xored_le[1] << 16 |
						first_offset_xored_le[2] << 8 |
						first_offset_xored_le[3]);

					//mul offset with fixed value 0x3333347B
					unsigned long long mul1 = (unsigned long long) first_offset_xored_int * 0x3333347B;

					//shifting to the right the upper part of the mul1 long long by 15
					unsigned int shift1 = (unsigned int)(mul1 >> 32) >> 0x15;

					//mul shift with fixed value 0x9FFFFC
					unsigned int mul2 = shift1 * 0x9FFFFC;

					//difference between offset1 and mul2 (acts like second offset xor key)
					unsigned int diff1 = first_offset_xored_int - mul2;

					//extract second xor key from decrypted keystream
					unsigned char* second_offset_xor = new unsigned char[4]();
					memcpy(second_offset_xor, decrypted_keystream + diff1, 4);

					//get second offset
					unsigned char* second_offset = new unsigned char[4]();
					memcpy(second_offset, decoded_extension_array + dim_decoded_extension - 4, 4);


					//second offset xored
					unsigned char* second_offset_xored = new unsigned char[4]();

					//xor second offset with second xor key extracted from decrypted keystream
					for (int i = 0; i < 4; i++)
					{
						second_offset_xored[i] = second_offset[i] ^ second_offset_xor[i];
					}

					//second offset xored to littleEndian
					unsigned char* second_offset_xored_le = new unsigned char[4]();
					second_offset_xored_le[0] = second_offset_xored[3];
					second_offset_xored_le[1] = second_offset_xored[2];
					second_offset_xored_le[2] = second_offset_xored[1];
					second_offset_xored_le[3] = second_offset_xored[0];

					//TO int
					unsigned int second_offset_xored_int = (second_offset_xored_le[0] << 24 |
						second_offset_xored_le[1] << 16 |
						second_offset_xored_le[2] << 8 |
						second_offset_xored_le[3]);


					//mul first_offset_xored_le with 0xCCCCCCCD
					unsigned long long mul3 = (unsigned long long) first_offset_xored_int * 0xCCCCCCCD;
					//mul second_offset_xored_le with 0xCCCCCCCD
					unsigned long long mul4 = (unsigned long long) second_offset_xored_int * 0xCCCCCCCD;

					//shifting to the right the upper part of the mul3 long long by 2
					unsigned int shift2 = (unsigned int)(mul3 >> 32) >> 0x2;

					//logic-AND between shift2 and 0x3FE00000
					unsigned int and1 = shift2 & 0x3FE00000;

					//mul and1 by 5 times
					unsigned int mul5 = and1 * 5;

					//REAL FIRST OFFSET FOR XOR KEY
					unsigned int real_first_XORKEY_offset = first_offset_xored_int - mul5;

					//shifting to the right the upper part of the mul4 long long by 2
					unsigned int shift3 = (unsigned int)(mul4 >> 32) >> 0x2;

					//logic-AND between shift3 and 0x3FE00000
					unsigned int and2 = shift3 & 0x3FE00000;

					//mul and1 by 5 times
					unsigned int mul6 = and2 * 5;

					//REAL SECOND OFFSET FOR XOR KEY
					unsigned int real_second_XORKEY_offset = second_offset_xored_int - mul6;

					//creating an output array of headerLen sie
					unsigned char* fileclear = new unsigned char[headerLen]();

					unsigned int mod_first_offset = 0;
					unsigned int mod_second_offset = 0;

					//decrypting the first headerLen bytes
					for (int i = 0; i < headerLen; i++)
					{
						mod_second_offset = i % 0x2FFF00;
						mod_first_offset = i % 0x2FFD00;

						fileclear[i] = decrypted_keystream[real_first_XORKEY_offset + mod_second_offset] ^
							decrypted_keystream[real_second_XORKEY_offset + mod_first_offset] ^
							file_encrypted[i];

					}

					
					//headerLen is the number of matching bytes
					if (strncmp(reinterpret_cast<const char*>(fileclear + 0), reinterpret_cast<const char*>(knownheader + 0), headerLen) == 0)
					{
							isOffsetNotFound = false;

							std::cout << "========= Offset FOUND: " << specialOffset << " (0x" << std::hex << specialOffset << ") ======== \n\n";
					}

					if (specialOffset > 0xFFFFFFFF)
					{
						std::cout << "========= Offset not found! ======== \n\n";
						isOffsetNotFound = false;

					}
					else
					{
						//
						specialOffset = specialOffset + 1;

					}

				


				}


				





			}



				








		}

	}
}



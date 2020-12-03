/*
	Author: John
	AES Crypter for 128-bit key size.

	Source: NIST FIPS Publication 197, Advanced Encryption Standard (AES) November 26, 2001

	Shellcode: execve-stack.nasm
	Key: "lookatthedefensetim
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

// Initialize MixColumns matrix
uint8_t mixer[4][4] = { {0x02, 0x03, 0x01, 0x01},
												{0x01, 0x02, 0x03, 0x01},
												{0x01, 0x01, 0x02, 0x03},
												{0x03, 0x01, 0x01, 0x02}
											};

// Define Rcon array
const uint8_t Rcon[16] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a };

// Define minimum length of input key
#define MIN_LENGTH	16


// Unencrypted shellcode goes here
unsigned char shellcode[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";


/*****************************************************************************************************/
/*  FUNCTIONS FOR ENCRYPTION ROUNDS
/*
/*
/*****************************************************************************************************/
// Cipher transformation that processes the state using S-box substitutions
void SubBytes(uint8_t state[4][4]){

	// Execute SubBytes function per 'Ch06 Crypto7e.pdf' pg. 12
	// Each byte is an index of row x column. Ex: 0x95 = row 9, column 5
	int i, j;
	for (i = 0; i<4; i++){
		for (j = 0; j<4; j++){
				// for each byte need to look up sbox at specific index and assign to spot
				state[i][j] = sbox[HI_NIBBLE(state[i][j])][LO_NIBBLE(state[i][j])];
			}
		}

	return;
}


// Cipher transformation that shifts last 3 rows by different offsets
void ShiftRows(uint8_t shiftedRows[4][4]){

	// Execute ShiftRows function per 'Ch06 Crypto7e.pdf' pg. 17
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
			temp = shiftedRows[row][0];
			// shift second row left 1 byte
			shiftedRows[row][0] = shiftedRows[1][1];
			shiftedRows[row][1] = shiftedRows[1][2];
			shiftedRows[row][2] = shiftedRows[1][3];
			shiftedRows[row][3] = temp;
		}
		else if (row == 2) {
			temp = shiftedRows[row][0];
			temp2 = shiftedRows[row][1];
			// shift third row left 2 bytes
			shiftedRows[row][0] = shiftedRows[2][2];
			shiftedRows[row][1] = shiftedRows[2][3];
			shiftedRows[row][2] = temp;
			shiftedRows[row][3] = temp2;
		}
		else {
			temp = shiftedRows[row][3];
			// shift fourth row left 3 bytes (or right 1 byte)
			shiftedRows[row][3] = shiftedRows[3][2];
			shiftedRows[row][2] = shiftedRows[3][1];
			shiftedRows[row][1] = shiftedRows[3][0];
			shiftedRows[row][0] = temp;
		}
	}

	return;
}

// Cipher transformation that takes all of the columns of the state and mixes their data to produce new columns
void MixColumns(uint8_t state[4][4]){
	// Execute MixColumns function per source: `angelfire.com/biz7/atleast/mix_columns.pdf`
	// character '<<' means left shift by x bits
	int i, j, k;
	uint8_t temp[4];
	uint8_t result[4][4] = { 0 };
	for (i = 0; i<4; ++i){
		for (j = 0; j<4; ++j) {
			for (k = 0; k<4; ++k){
				// Iterate over COLUMNS in state, while iterating by Mixer ROWS on the outside loop
				// hence mixer[i][k] and state[k][j]
				if (mixer[i][k] == 0x01){
					// Do normal multiplication (0x01 * column value)
					result[i][j] ^= mixer[i][k]*state[k][j];
				}
				else if (mixer[i][k] == 0x02){
					// slightly more complicated instructions
					// left shift state[i][j] value 1 byte then XOR with 0x1b if leftmost bit is 1
					// source: `cs.purdue.edu/homes/ssw/cs655/rij.pdf`
						if (HI_NIBBLE(state[k][j]) >= 8){
							result[i][j] ^= (state[k][j] <<1) ^ 0x1b;
						}
						else {
							result[i][j] ^= (state[k][j] << 1);
						}
				}
				else {
						// Same instructions as mixer[j][i] == 0x02 with an additional XOR of state[k][j]
						if (HI_NIBBLE(state[k][j]) >= 8){

							result[i][j] ^= (state[k][j] <<1) ^ 0x1b;
						}
						else {
							result[i][j] ^= (state[k][j] << 1);
						}
						result[i][j] ^= state[k][j];
				} // end else
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

// Cipher transformation that processes the state using S-box substitutions
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


// Main cipher function that calls sub-functions in order: SubBytes(), ShiftRows(), MixColumns(), and AddRoundKey()
// RoundKey is produced in the key expansion function, ExpandKey(),
void Cipher(uint8_t state[4][NB], uint8_t keySchedule[44][NB]){
	/*
		Cipher function performs the actual encryption operations on 16-byte blocks
		of plaintext and keys.

		plaintext matrix is already set (from state[][]) but Key Expansion must take
		place in ExpandKey(). Round keys are loaded into inputKey[4][4] one round at a time.

		Refer to 'Ch06 Crypto7e.pdf' pgs. 4 & 7
	*/

	// Load first 4 words of keySchedule[][] for use with AddRoundKey()
	uint8_t inputKey[4][4] = { 0 };
	int a, b;
	for (a = 0; a< 4; a++) {
		for (b = 0; b<4; b++) {
			inputKey[b][a] = keySchedule[a][b];
		}
	}

	// Call first instance of AddRoundKey() before continuing with normal rounds
	AddRoundKey(state, inputKey);

	// Perform encryption rounds
	// Call SubBytes(), ShiftRows(), MixColumns(), and AddRoundKey() 13 times
	for (int i = 1; i < NR; i++) {

		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);


		// Load round key from keySchedule for use in AddRoundKey
		int row, col;
		for (row = i*NB; row< (i*NB)+4; row++) {
			for (col = 0; col<4; col++) {
				inputKey[col][row - (i*NB)] = keySchedule[row][col];
				}
			}

			// This index should be a multiple of 4 increasing from 4 up to 40
			AddRoundKey(state, inputKey);

	} // end round iterations loop

	// Omit MixColumns() for final round; else proceed with SubBytes(),
	// ShiftRows(), and AddRoundKey() in order
	SubBytes(state);
	ShiftRows(state);

	// Load last 4 words from keySchedule for final AddRoundKey
	int c, d;
	for (c = 40; c< 44; c++) {
		for (d = 0; d<4; d++) {
			inputKey[d][c-40] = keySchedule[c][d];
		}
	}
	// 40 is the starting index of last 4 words: 40, 41, 42, 43
	AddRoundKey(state, inputKey);

	return;
} // end Cipher function



int main(int argc, char **argv) {
/*
	Main function divides plaintext and keys into 16-byte blocks for operation by
	Cipher() function
							*/
	unsigned char *encryption_key;
	int encryption_key_length;
	int shellcode_len = strlen(shellcode);

	// Extract key parameter and get its length
	encryption_key = (unsigned char *)argv[1];
	encryption_key_length = strlen((char *)encryption_key);

	if (encryption_key_length < 16) {
		printf("Key too small. Should be minimum 16 characters\n");
		exit(-1);
	}

	// Number of full rounds.  "Full" means 16 bytes of state[4][4] are filled
	// with shellcode bytes and not padding.
	int rounds = shellcode_len / 16;

	// Index counters to traverse shellcode and encryption_key bytes. These are
	// initialized to zero and set outside the loop
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

	// Expand the 4x4 key
	uint8_t key_expanded[44][4] = { 0 };
	ExpandKey(key, key_expanded);

	printf("Dumping AES-128 Encrypted Shellcode\n\n\n\"");
	// MASTER LOOP
	// Load groups of 16 bytes of shellcode into state[4][4]
	if (shellcode_len % 16 == 0) {
		// if shellcode is a multiple of 16 do NOT perform the extra encryption round full of
		// padded bytes
		for (iterations = 0; iterations < rounds; iterations++){

			// Execute byte loading instructions for state
			int i, j;
			for (j = 0; j<4; j++){
				for (i = 0; i<4; i++){
					if (shell_index < shellcode_len) {
						// end of shellcode not reached. Store shellcode bytes normally.
						state[i][j] = shellcode[shell_index];
					}
					else {
						// Pad rest of matrix with 0x0f if end of shellcode reached.
						state[i][j] = 0x0f;
					}
					shell_index += 1;
				}
			}

			// Execute Cipher with loaded state matrix
			// Pass state and expanded key into cipher function over number of iterations
			Cipher(state, key_expanded);

			for (int c = 0; c<4; c++){
				for (int d = 0; d<4; d++){
					printf("\\x%02x", state[d][c]);
				}
			}
		} // end iterations loop
	} // end shellcode_len modulo check
	// else perform normal encryption routine
	else {
		for (iterations = 0; iterations <= rounds; iterations++){

			// Execute byte loading instructions for state
			int i, j;
			for (j = 0; j<4; j++){
				for (i = 0; i<4; i++){
					if (shell_index < shellcode_len) {
						// end of shellcode not reached. Store shellcode bytes normally.
						state[i][j] = shellcode[shell_index];
					}
					else {
						// Pad rest of matrix with 0x0f if end of shellcode reached.
						state[i][j] = 0x0f;
					}
					shell_index += 1;
				} // end i
			} // end j

			// Execute Cipher with loaded state matrix
			// Pass state and expanded key into cipher function over number of iterations
			Cipher(state, key_expanded);

			for (int c = 0; c<4; c++){
				for (int d = 0; d<4; d++){
					printf("\\x%02x", state[d][c]);
				}
			}
		} // end iterations routine
	}  // End MASTER LOOP

	// end shellcode with double quote
	printf("\"\n\n");
	return 1;

}

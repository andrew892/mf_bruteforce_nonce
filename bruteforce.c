#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include<string.h>

#include "crapto1.h"

char calc_parity(char byte);
uint16_t xored_bits(uint16_t nt_par, uint32_t nt_enc, uint16_t ar_par, uint32_t ar_enc, uint16_t at_par, uint32_t at_enc);
char valid_nonce(uint32_t xored, uint32_t nt);

int main() {
	
	// input
	uint32_t uid	= 0x00000000;	// uid
	uint32_t nt_enc = 0x00000000;	// encrypted tag challenge
	uint32_t nr_enc = 0x00000000;	// encrypted reader challenge
	uint32_t ar_enc = 0x00000000;	// encrypted reader response
	uint32_t at_enc = 0x00000000;	// encrypted tag response
	
	uint16_t nt_par = 0x0000;
	uint16_t ar_par = 0x0000;
	uint16_t at_par = 0x0000;
	// end_input
	
	//calc (parity XOR corresponding nonce bit encoded with the same keystream bit)
	uint16_t xored = xored_bits(nt_par, nt_enc, ar_par, ar_enc, at_par, at_enc);
	
	struct Crypto1State *revstate;
	uint64_t key;
	uint32_t ks2;
	uint32_t ks3;
	uint32_t ks4;
	uint32_t nt;
	int rolled_bytes = 0;
	
	for(nt=0x00000000; nt < 0x0000ffff; nt++) {
		//~ sleep(1);
		
		if(valid_nonce(xored, nt)) {
			printf("nt: %08x...\n", nt);
			rolled_bytes = 0;
			ks2 = ar_enc ^ prng_successor(nt, 64);
			ks3 = at_enc ^ prng_successor(nt, 96);
			revstate = lfsr_recovery64(ks2, ks3);
			
			ks4 = crypto1_word(revstate,0,0);
			rolled_bytes +=4;

			if (ks4 != 0) {
				printf("\n**** Key candidate found ****\n");
				printf("current nt:%08x\n", nt);
				printf("current ar_enc:%08x\n", ar_enc);
				printf("current at_enc:%08x\n", at_enc);
				printf("ks2:%08x\n", ks2);
				printf("ks3:%08x\n", ks3);
				printf("ks4:%08x\n", ks4);
				//~ printf("enc cmd:\t%08x\n", enc_4);		
				//~ if(enc_4) {			
					//~ printf("decrypted cmd:\t%08x\n", ks4^enc_4);
				//~ }				
				for(int i=0; i<rolled_bytes; i++) {
					lfsr_rollback_byte(revstate,0,0);
				}

				lfsr_rollback_word(revstate, 0, 0);
				lfsr_rollback_word(revstate, 0, 0);
				lfsr_rollback_word(revstate, nr_enc, 1);
				lfsr_rollback_word(revstate, uid ^ nt, 0);
				crypto1_get_lfsr(revstate, &key);
				printf("\nKey candidate: [%012lx]\n\n",key);
				return 0;
			}
			crypto1_destroy(revstate);
		}
	}
	
	return 0;
}

char calc_parity(char byte) {
	char par = 0x0;
	int i;
	for(i=0; i<8; i++) {
		par = par ^ (byte & 0x1);
		byte = byte >> 1;
	}
	return (par ^ 0x1); //odd parity
}

uint16_t xored_bits(uint16_t nt_par, uint32_t nt_enc, uint16_t ar_par, uint32_t ar_enc, uint16_t at_par, uint32_t at_enc) {
	uint16_t xored = 0x0000;
	
	char par;
	//1st (1st nt)
	par = (nt_par & 0x1000) >> 12;
	xored = xored | ( par ^ ((nt_enc & 0x00010000) >> 16) );
	xored = xored << 1;
	//2nd (2nd nt)
	par = (nt_par & 0x0100) >> 8;
	xored = xored | ( par ^ ((nt_enc & 0x00000100) >> 8) );
	xored = xored << 1;
	//3rd (3rd nt)
	par = (nt_par & 0x0010) >> 4;
	xored = xored | ( par ^ (nt_enc & 0x00000001) );
	xored = xored << 1;
	//4th (1st ar)
	par = (ar_par & 0x1000) >> 12;
	xored = xored | ( par ^ ((ar_enc & 0x00010000) >> 16) );
	xored = xored << 1;
	//5th (2nd ar)
	par = (ar_par & 0x0100) >> 8;
	xored = xored | ( par ^ ((ar_enc & 0x00000100) >> 8) );
	xored = xored << 1;
	//6th (3rd ar)
	par = (ar_par & 0x0010) >> 4;
	xored = xored | ( par ^ (ar_enc & 0x00000001) );
	xored = xored << 1;
	//7th (4th ar)
	par = (ar_par & 0x0001);
	xored = xored | ( par ^ ((at_enc & 0x01000000) >> 24) );
	xored = xored << 1;
	//8th (1st at)
	par = (at_par & 0x1000) >> 12;
	xored = xored | ( par ^ ((at_enc & 0x00010000) >> 16) );
	xored = xored << 1;
	//9th (2nd at)
	par = (at_par & 0x0100) >> 8;
	xored = xored | ( par ^ ((at_enc & 0x00000100) >> 8) );
	xored = xored << 1;
	//10th (3rd at)
	par = (at_par & 0x0010) >> 4;
	xored = xored | ( par ^ (at_enc & 0x00000001) );
	
	return xored;
}

char valid_nonce(uint32_t magic, uint32_t nt) {
	char byte;
	char check;
	
	//1st (1st nt)
	//~ byte = (nt & 0xff000000) >> 24;
	//~ check = calc_parity(byte) ^ ((nt & 0x00010000) >> 16) ^ ((magic & 0x0200) >> 9);
	//~ if(check)
		//~ return 0;
		
	//2nd (2nd nt)
	//~ byte = (nt & 0x00ff0000) >> 16;
	//~ check = calc_parity(byte) ^ ((nt & 0x00000100) >> 8) ^ ((magic & 0x0100) >> 8);
	//~ if(check)
		//~ return 0;
		
	//3rd (3rd nt)
	byte = (nt & 0x0000ff00) >> 8;
	check = calc_parity(byte) ^ (nt & 0x00000001) ^ ((magic & 0x0080) >> 7);
	if(check) {
		return 0;
	}
	
	uint32_t ar = prng_successor(nt, 64);
	
	//4th (1st ar)
	byte = (ar & 0xff000000) >> 24;
	check = calc_parity(byte) ^ ((ar & 0x00010000) >> 16) ^ ((magic & 0x0040) >> 6);
	if(check) {
		return 0;
	}
	
	//5th (2nd ar)
	byte = (ar & 0x00ff0000) >> 16;
	check = calc_parity(byte) ^ ((ar & 0x00000100) >> 8) ^ ((magic & 0x0020) >> 5);
	if(check) {
		return 0;
	}
	
	//6th (3rd ar)
	byte = (ar & 0x0000ff00) >> 8;
	check = calc_parity(byte) ^ (ar & 0x00000001) ^ ((magic & 0x0010) >> 4);
	if(check) {
		return 0;
	}
		
	uint32_t at = prng_successor(nt, 96);
		
	//7th (4th ar)
	byte = (ar & 0x000000ff);
	check = calc_parity(byte) ^ ((at & 0x01000000) >> 24) ^ ((magic & 0x0008) >> 3);
	if(check) {
		return 0;
	}
	
	//8th (1st at)
	byte = (at & 0xff000000) >> 24;
	check = calc_parity(byte) ^ ((at & 0x00010000) >> 16) ^ ((magic & 0x0004) >> 2);
	if(check) {
		return 0;
	}
	
	//9th (2nd at)
	byte = (at & 0x00ff0000) >> 16;
	check = calc_parity(byte) ^ ((at & 0x00000100) >> 8) ^ ((magic & 0x0002) >> 1);
	if(check) {
		return 0;
	}
	
	//10th (3rd at)
	byte = (at & 0x0000ff00) >> 8;
	check = calc_parity(byte) ^ (at & 0x00000001) ^ ((magic & 0x0001));
	if(check) {
		return 0;
	}
		
	return 1;
}

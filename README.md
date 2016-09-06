# mf_bruteforce_nonce
Key recovering tool from nested authentication in Mifare Classic sniffed traces.

Compiling and executing:

	gcc bruteforce.c crypto1.c crapto1.c -o bruteforce && ./bruteforce

This tool uses parity information leak to speed-up bruteforce and get a candidate key in less then a minute.  
**If the tag isn't the lastest version of mifare classic (EV1), this tool can recover directly the key.**

	syntax: ./bruteforce <uid> <{nt}> <nt_par_err> <{nr}> <{ar}> <ar_par_err> <{at}> <at_par_err> [<{next_command}>]
	
Where:
* ``{nt}`` is the encrypted tag nonce
* ``nt_par_err`` are 4 parity error bits of nt
* ``{nr}`` is the encrypted reader nonce
* ``{ar}`` is the encrypted reader answer
* ``ar_par_err`` are 4 parity error bits of ar
* ``{at}`` is the encrypted tag answer
* ``at_par_err`` are 4 parity error bits of at
* ``{next_command}`` is the encrypted command after authentication

Example of error bits input:

	8c!  42 e6! 4e!    nt in trace
	8c42e64e           nt to pass as parameter
	1011               parity errors to pass as parameter (! means 1 ; no ! means 0)

Once you got the candidate key ``[XXXXZZZZZZZZ]``, the ``ZZ`` bytes are correct.  
You have to get the ``XX`` bytes with 2nd phase of bruteforce, online on the card, testing all possible combinations.

The second phase is here: https://github.com/J-Run/mf_key_brute

----

This project is based on J-Run bruteforce tool:
https://github.com/J-Run/mf_nonce_brute

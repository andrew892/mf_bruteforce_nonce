# mf_bruteforce_nonce
Key recovering tool from nested authentication in Mifare Classic sniffed traces.

This tool uses parity information leak to speed-up bruteforce and get a candidate key in less then a minute.

 syntax: ./bruteforce <uid> <nt> <nt_par_err> <nr> <ar> <ar_par_err> <at> <at_par_err> [<next command>]

 example:   nt in trace = 8c!  42 e6! 4e!
                     nt = 8c42e64e
             nt_par_err = 1011

once you got the candidate key [XXXXZZZZZZZZ], the ZZ bytes are correct.
You have to get the XX's one with 2nd phase of bruteforce, online on the card, testing all possible combinations.

The second phase is here: https://github.com/J-Run/mf_key_brute

----

This project is based on J-Run bruteforce tool:
https://github.com/J-Run/mf_nonce_brute

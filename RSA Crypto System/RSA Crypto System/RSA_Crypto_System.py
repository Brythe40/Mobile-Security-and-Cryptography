# Mobile Security and Cryptography Problem 2
# RSA Crypto System
# Bryce Olivier, Robert Spampneto, Harrison Bourg, and Brennan Butler
from Prime_Checker import Prime_Checker


#print("Enter a number: ")
#num = int(input())

#pchecker = Prime_Checker.check_prime(num)
primes = Prime_Checker.get_primes()
p = primes[9]
q = primes[18]
n = p * q
e = 65537
d = Prime_Checker.inverse_mod(e, (p - 1) * ( q - 1))

public_key = {'e': e, 'n': n}
private_key = {'d': d, 'p': p, 'q': q}


print("public: ", public_key)
print("private: ", private_key)

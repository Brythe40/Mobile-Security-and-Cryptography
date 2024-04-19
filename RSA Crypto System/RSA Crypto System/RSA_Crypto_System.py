# Mobile Security and Cryptography Problem 2
# RSA Crypto System
# Bryce Olivier, Robert Spampneto, Harrison Bourg, and Brennan Butler

from Prime_Checker import prime_checker


print("Enter a number: ")
num = int(input())
pchecker = prime_checker().check_prime(num, 2)
print(str(num) + "'s prime value is: " + str(pchecker))

from tokenize import Number
import time


class Prime_Checker:
    # check if number is prime, boolean
    def check_prime(number):
        # corner case
        if(number <=1): 
            return False
        # check prime
        if(number <= 3): 
            return True
        # base case
        if(number % 2 == 0 or number % 3 == 0): 
            return False
        i = 5
        while i * i <= number:
            if number % i == 0 or number % (i + 2) == 0:
                return False
            i += 6
        return True

        return self.check_prime(number, iterator)

    # get 10th (p) and 19th (q) prime numbers between 1,000 and 10,000
    def get_primes(number):
        primes = []
        while len(primes) < 19:
            if Prime_Checker.check_prime(number):
                primes.append(number)
            number += 1
        return primes

    # get the inverse modulous
    def inverse_mod(e, phi):
        original_e = e
        y = 0
        x = 1

        if e == 1: return 0

        while e > 1:
            q = e // phi
            temp = phi
            phi = e % phi
            e = temp
            temp = y
            y = x - q * y
            x = temp

        if x < 0: x = x + original_e
        return x

    def encrypt(message, key):
        e = key['e']
        n = key['n']
        encrypted = [(ord(char) - ord('a'))**e % n for char in message]
        return encrypted

    def decrypt(message, key):
        d = key['d']
        print("private key d: ", d)
        p = key['p']
        q = key['q']
        n = p * q
        decrypted = [chr((char**d) % n + ord('a')) for char in message]
        return ''.join(decrypted)

    def exhaustive_search(key):
        print("Starting exhaustive search...")
        e = key['e']
        n = key['n']
        start_time = time.time()
        d = 2
        while True:
            if (e * d) % Prime_Checker.phi(n) == 1:
                break
            d += 1
        end_time = time.time()
        print("Exhuastive search found private key (d): ", d, " in ", end_time - start_time, "seconds")

    def phi(number):
        result = 1
        p = 2
        while p * p <= number:
            if number % p == 0:
                count = 0
                while number % p == 0:
                    number //= p
                    count += 1
                result *= (p - 1) * p**(count - 1)
            p += 1
        if number > 1:
            result *= number - 1
        return result

    pass

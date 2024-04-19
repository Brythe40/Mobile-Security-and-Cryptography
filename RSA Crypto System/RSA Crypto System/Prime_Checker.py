from tokenize import Number


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
    def get_primes():
        primes = []
        number = 1000
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
    pass

class prime_checker:
    def check_prime(self, number, iterator):
        # corner case
        if(number == 0 or number ==1): 
            return False
        # check prime
        if(number == iterator): 
            return True
        # base case
        if(number % iterator == 0): 
            return False
        iterator += 1

        return self.check_prime(number, iterator)
    pass

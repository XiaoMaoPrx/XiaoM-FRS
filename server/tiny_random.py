from datetime import datetime

class TinyRandom:
    def timestamp(self):
        seed = datetime.now().timestamp() * 1000000
        return seed
    def xorshift(self, seed):
        seed = int(seed)
        seed ^= (seed << 13) & 0xFFFFFFFF
        seed ^= (seed >> 17) & 0xFFFFFFFF
        seed ^= (seed << 5) & 0xFFFFFFFF
        return seed
    def lcg(self, seed, a=1664525, c=1013904223, m=2**32):
        return (a * seed + c) % m
    def random_float(self, min_val, max_val, seed=None):
        if seed is None:
            seed = self.xorshift(self.timestamp()*3)
        random_value = self.lcg(seed) / (2**32)
        return min_val + (max_val - min_val) * random_value
    def random(self, min_val, max_val, seed=None):
        if seed is None:
            seed = self.xorshift(self.timestamp()*3)
        random_value = self.lcg(seed) / (2**32)
        return min_val + int((max_val - min_val + 1) * random_value)
    def random_list(self, lst, seed=None):
        if seed is None:
            seed = self.xorshift(self.timestamp()*3)
        list_len = len(lst)
        return lst[self.random(0, list_len - 1, seed)]
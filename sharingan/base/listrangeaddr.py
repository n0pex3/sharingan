class RangeAddr:
    def __init__(self):
        self.start_ea = 0
        self.end_ea = 0
        self.name = ''

    def __str__(self):
        return f'Range address: {hex(self.start_ea)} - {hex(self.end_ea)} - {self.byte_code}'

    
class ListRangeAddr:
    def __init__(self, allowed_type):
        self.items = []
        self.allowed_type = allowed_type

    def append(self, item):
        if not isinstance(item, self.allowed_type):
            raise TypeError(f"Item must be of type {self.allowed_type.__name__}, got {type(item).__name__}")
        self.items.append(item)

    def insert(self, index, item):
        if not isinstance(item, self.allowed_type):
            raise TypeError(f"Item must be of type {self.allowed_type.__name__}, got {type(item).__name__}")
        self.items.insert(index, item)
    
    def __getitem__(self, index):
        return self.items[index]
    
    def __setitem__(self, index, item):
        if not isinstance(item, self.allowed_type):
            raise TypeError(f"Item must be of type {self.allowed_type.__name__}, got {type(item).__name__}")
        self.items[index] = item
    
    def __len__(self):
        return len(self.items)
    
    def __str__(self):
        return str(self.items)
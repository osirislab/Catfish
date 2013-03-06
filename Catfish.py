from collections import OrderedDict
from pprint import PrettyPrinter
import objects, sys

class Catfish():
    def __init__(self):
        self.gadget_library = objects.Library()
        self.gadgets = {}
        self.modules = []
        self.stack = []
    def add_module_by_filename(self, filename):
        module = objects.Module(filename)
        return self.add_module_by_object(module)
    def add_module_by_object(self, module):
        # Search module for returns (including returning w/ offset)
        returns = module.findallbytesre('(?:\xc3|\xc2[\x00-\xFF]{2}){1}')
        gcount = 0
        for i in range(24):
            for ret in returns:
                current = module.decoderange(ret-i, ret+1)
                if current and current[max(current.keys())] == 'RET':
                    # Arbitrary limit of 5 instructions per gadget
                    if len(current) <= 5:
                        self.gadget_library.add_gadget(objects.Gadget(ret-1, current))
                        instruction = current[min(current.keys())]
                        if instruction in self.gadgets.keys():
                            self.gadgets[instruction].append(current)
                        else:
                            self.gadgets[instruction] = [current]
                        # self.gadgets.append(current)
                        gcount += 1
        self.modules.append(module)
        return gcount
    def find_instruction(self, instruction):
        try:
            instructions = self.gadgets[instruction]
        except KeyError:
            return None
        shortest = instructions[0]

        for i in instructions:
            # shortest sequuuuence found
            if len(i) == 2:
                return i
            if len(i) < len(shortest):
                shortest = i

        return shortest
    def find_instruction_regex(self, instruction):
        return
    def find_call(self, function):
        # fails to find calls
        print self.modules
        for module in self.modules:
            for i in module.imports:
                if i.Name == function:
                    VA = i.VA
                    # Don't judge me!
                    VA = hex(VA)[2:].zfill(8).decode('hex')[::-1]
                    results = module.findallbytesre('\xff\x15' + VA)
                    if not results:
                        return None
                    else:
                        return results
        return None
    def add_to_stack(self, value):
        self.stack.append(value)
    def assemble(self):
        return self.stack.join('')

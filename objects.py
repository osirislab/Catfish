from collections import OrderedDict
import distorm3, dislib, re, sys

class Library:
    def __init__(self):
        self.gadgets = {}
        self.stack = []
        self.maxcompensate = 8
    def add_gadget(self, gadget):
        if gadget.instruction not in self.gadgets.keys():
            self.gadgets[gadget.instruction] = []
        self.gadgets[gadget.instruction].append(gadget)
    def find_gadget(self, instruction, return_random=False):
        if instruction in self.gadgets.keys():
            smallest = self.gadgets[instruction][0]
            print "%d duplicates" % len(self.gadgets[instruction])
            for i in self.gadgets[instruction]:
                print len(i.instructions)
            for gadget in self.gadgets[instruction]:
                if len(gadget.instructions) < len(smallest.instructions):
                    smallest = gadget
            print smallest.instructions
            return smallest
            index = 0
            # XXX: If multiple gadgets, return a random equivalent
            found = self.gadgets[instruction][0]
            if found.compensate > self.maxcompensate:
                raise ValueError("Required stack compensation (%d bytes) exceeds maximum of %d bytes" % (found.compensate, self.maxcompensate))
            return self.gadgets[instruction][0]
        raise ValueError("No instruction matching %s found" % (instruction))
        return False
    def chain(self, instruction):
        found = self.find_gadget(instruction)
        self.stack.append(hex(found.location))
        if found.compensate > 0:
            temp = found.compensate/4
            while temp > 0:
                self.stack.append("0x41414141")
                temp -= 1
        return self
    def add_static(self, value):
        self.stack.append(value)
    def assemble(self):
        return self.stack

class Gadget:
    def __init__(self, module, instructions):
        self.module = module
        self.instructions = instructions
        self.instruction = instructions[min(instructions.keys())]
        self.location = min(instructions.keys())
        self.rawbytes = ''
        self.modify = []
        self.read = []
        self.registers = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
        self.compensate = 0
        self.parse_gadget()
    def parse_gadget(self, return_offset=0):
        for key in self.instructions.keys():
            self.parse_instruction(self.instructions[key])
    def parse_instruction(self, instruction):
        # XXX: Figure out a better way to parse instructions
        instruction = instruction.replace(',','').split(' ')
        if instruction[0] == 'POP':
            self.modify.append(instruction[1])
            self.read.append('stack')
        elif instruction[0] == 'PUSH':
            self.modify.append('stack')
            self.read.append(instruction[1])
        elif instruction[0] == 'INC':
            self.modify.append(instruction[1])
        elif instruction[0] == 'DEC':
            self.modify.append(instruction[1])
        elif instruction[0] == 'XOR':
            self.modify.append(instruction[1])
            self.read.append(instruction[2])
        elif instruction[0] == 'RET':
            if len(instruction) == 1:
                return
            # There's probably a better way...
            exec "self.compensate=" + instruction[1]

class Module:
    def __init__(self, filename):
        self.peobj = dislib.PEFile(filename)
        # print self.peobj.codesize
        self.filename = filename
        self.imagebase = self.peobj.ImageBase
        self.entrypoint = self.peobj.EntryPoint
        self.textsec = self.peobj.GetSectionByVA(self.entrypoint)
        # self.textsegment = self.textsec.Data[self.peobj.EntryPoint - self.textsec.VA:][:20*1024]
        self.textsegment = self.textsec.Data[self.peobj.EntryPoint - self.textsec.VA:]
        self.imports = self.peobj.Imports
    def decoderange(self, start_address, end_address):
        start_offset = start_address - (self.imagebase + self.entrypoint)
        end_offset = end_address - (self.imagebase + self.entrypoint)
        results = OrderedDict()
        decoded = distorm3.Decode(self.imagebase + self.entrypoint + start_offset, self.textsec.Data[self.entrypoint - self.textsec.VA:][start_offset:end_offset], distorm3.Decode32Bits)
        for instr in decoded:
            results[instr[0]] = instr[2]
        return results
    def decodeaddress(self, address):
        offset = address - (self.imagebase + self.entrypoint)
        decoded = distorm3.Decode(self.imagebase + self.entrypoint + offset, self.textsec.Data[self.entrypoint - self.textsec.VA:][offset::], distorm3.Decode32Bits)
        for instr in decoded:
            print "0x%08x (%02x) %-20s %s" % (instr[0], instr[1], instr[3], instr[2])
            return
            raw_input()
        return
    def decodeuntilret(self, address):
        offset = address - (self.imagebase + self.entrypoint)
        # decoded = distorm3.Decode(self.imagebase + self.entrypoint + offset, self.textsec.Data[self.entrypoint - self.textsec.VA:][:4*1024][slice(offset, self.textsec.Data[self.entrypoint - self.textsec.VA:][:4*1024].index('\xc3', offset)+1)], distorm3.Decode32Bits)
        # decoded = distorm3.Decode(self.imagebase + self.entrypoint + offset, self.textsec.Data[self.entrypoint - self.textsec.VA:][:20*1024][offset::], distorm3.Decode32Bits)
        decoded = distorm3.Decode(self.imagebase + self.entrypoint + offset, self.textsec.Data[self.entrypoint - self.textsec.VA:][offset::], distorm3.Decode32Bits)
        results = OrderedDict()
        for instr in decoded:
            # print "    0x%08x (%02x) %-20s %s" % (instr[0], instr[1], instr[3], instr[2])
            # print "    %s" % (instr[2])
            # results.append(instr[2])
            results[instr[0]] = instr[2]
            # results[instr[0]] = instr[2]
            if instr[3] == "c3" or instr[2][:3] == "RET":
                return results
        return OrderedDict()
    def findbytes(self, bytes, index=0):
        try:
            return self.imagebase + self.entrypoint + self.textsegment.index(bytes, index)
        except ValueError:
            return []
    def findbytesre(self, bytes, index=0):
        expression = re.compile(bytes)
        results = expression.findall(self.textsegment)
        addresses = []
        # http://stackoverflow.com/questions/3519565/find-the-indexes-of-all-regex-matches-in-python
        results = list(set(results))
        for result in results:
            addresses.append(self.imagebase + self.entrypoint + self.textsegment.index(result))
        return addresses
    def findallbytesre(self, bytes):
        expression = re.compile(bytes)
        results = expression.findall(self.textsegment)
        return [self.imagebase + self.entrypoint + m.start(0) for m in expression.finditer(self.textsegment)]
        addresses = []
        # http://stackoverflow.com/questions/3519565/find-the-indexes-of-all-regex-matches-in-python
        results = list(set(results))
        for result in results:
            addresses.append(self.imagebase + self.entrypoint + self.textsegment.index(result))
        return addresses
    def decodebytes(self, bytes):
        return
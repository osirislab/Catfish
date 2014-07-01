from capstone import *
import bintools.elf
import struct
import dislib
import re

class Segment:
    def __init__(self, name, base, code):
        self.name = name
        self.base = base
        self.code = code

class Gadget:
    def __init__(self, byte_sequence, instructions, offset, segment, padding=0):
        self.byte_sequence = byte_sequence
        self.instructions = instructions
        self.base = segment.base + offset
        self.padding = padding
        self.segment_name = segment.name

    def __str__(self):
        return "%s%s: %s" % ("%s@"%self.segment_name, hex(self.base), '; '.join(self.instructions))

class Module:
    def __init__(self, path, architecture):
        self.name = path.split("/")[-1]
        self.segments = []
        self.text_segment = None
        self.architecture = architecture
        if self.architecture.lower() == "x86":
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.architecture.lower() == "x86_64":
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        elif self.architecture.lower() == "x86_16": # lol
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
        else:
            raise Exception("I donut know that architecty")
        self.load(path)

    def load(self, path):
        raise("NO")

    def find_all_bytes(self, segment, byte_sequence):
        for i in re.finditer(byte_sequence, segment.code):
            if i.group(0)[-1] == "\xc3":
                padding = 0
            else:
                padding = struct.unpack("H", i.group(0)[-2:])[0]

            yield self.build_gadget(i.group(0), i.start(), segment)

    def find_all_returns(self, segment, offset=True):
        if offset:
            return self.find_all_bytes(segment, '(?:\xc3|\xc2[\x00-\xFF]{2}){1}')
        return self.find_all_bytes(segment, '\xc3')

    def find_all_gadgets(self, lookback, offset=False, remove_dupes=True):
        start_addresses = []
        sequences = []

        for segment in self.segments:
            for gadget in self.find_all_returns(segment, offset):
                gadget_location = gadget.base-segment.base
                gadget_length = len(gadget.byte_sequence)
                # start at 1 instead of 0 or else you get all rets by default
                for offset in range(1, lookback*15):
                    # don't even look at gadgets that have been examined already
                    if gadget_location-offset in start_addresses or gadget_location-offset < 0:
                        continue

                    byte_sequence = segment.code[gadget_location-offset:gadget_location+gadget_length]
                    temp_gadget = self.build_gadget(byte_sequence, gadget_location-offset, segment)

                    if remove_dupes:
                        if str(temp_gadget).split(": ")[1] in sequences:
                            continue

                        sequences.append(str(temp_gadget).split(": ")[1])

                    if len(temp_gadget.instructions) == lookback:
                        # if there is a ret in the middle of the gadget, abort
                        abort = False
                        for index, value in enumerate(temp_gadget.instructions):
                            if "ret" in value and index != len(temp_gadget.instructions)-1:
                                abort = True
                                break

                        if abort:
                            continue

                        # sometimes the last instruction is not actually a return
                        if "ret" not in temp_gadget.instructions[-1]:
                            continue
                        yield temp_gadget

    def build_gadget(self, byte_sequence, offset, segment):
        instructions = []
        for instruction in self.disassembler.disasm(byte_sequence, segment.base+offset):
            instructions.append("%s %s"%(instruction.mnemonic, instruction.op_str))

        return Gadget(byte_sequence, instructions, offset, segment)

class PE(Module):
    def load(self, path):
        self.binary = dislib.PEFile(path)
        self.entry_point = entry_point = self.binary.ImageBase + self.binary.EntryPoint
        text_section = self.binary.GetSectionByVA(self.binary.EntryPoint)
        code = text_section.Data[self.binary.EntryPoint - text_section.VA:]
        self.text_segment = Segment(".text", self.entry_point, code)
        self.segments.append(self.text_segment)

class ELF(Module):
    def load(self, path):
        import sys
        self.binary = bintools.elf.ELF(path)
        self.imagebase = self.binary.header.entry
        self.entry_point = self.binary.sect_dict['.text'].addr
        self.text_segment = Segment("text", self.entry_point, self.binary.sect_dict['.text'].data)
        for segment in self.binary.sect_dict:
            current_segment = self.binary.sect_dict[segment]
            if current_segment.is_loadable() and current_segment.is_execinstr():
                self.segments.append(Segment(segment, current_segment.addr, current_segment.data))
                if segment == '.text':
                    self.text_segment = Segment(segment, current_segment.addr, current_segment.data)

class Raw(Module):
    def load(self, path):
        self.binary = None
        self.entry_point = 0
        self.text_segment = Segment(".text", self.entry_point, path)
        self.segments.append(self.text_segment)

from Catfish import Catfish
from pprint import PrettyPrinter
import objects

c = Catfish()
pp = PrettyPrinter(indent=4)
cmds = raw_input("> ")

while 1 and cmds:
    cmds = cmds.split(' ')
    if cmds[0] == "what":
        print 'yes'
    elif cmds[0] == "load":
        c.add_module_by_filename(cmds[1])
    elif cmds[0] == "write":
        handle = open(cmds[1], 'wb')
        for entry in c.stack[::-1]:
            # hand-wavy black magic
            handle.write(hex(entry)[2:].replace('L', '').zfill(8).decode('hex')[::-1])
        handle.close()
    elif cmds[0] == "display":
        pp.pprint(c.stack)
    elif cmds[0] == "static":
        c.add_to_stack(int(cmds[1], 16))
    elif cmds[0] == "call":
        instruction = c.find_call(cmds[1])
        if instruction:
            print instruction
            c.add_to_stack(instruction[0])
        else:
            print "Couldn't find a call to that function..."
    elif cmds[0] == "list":
        try:
            thing = cmds[1]
        except IndexError:
            thing = "gadgets"
        if thing == "imports":
            print "Here are the functions you can call from the IAT:"
            for module in c.modules:
                print module.imports
        elif thing == "gadgets":
            pp.pprint(c.gadgets)
    elif cmds[0] == "help":
        print "You're on your own"
    else:
        instruction = c.find_instruction(' '.join(cmd for cmd in cmds))
        if instruction:
            c.add_to_stack(instruction.keys()[0])
        else:
            print "Couldn't find that instruction..."
    cmds = raw_input("> ")
import Module, sys

if len(sys.argv) < 2:
    print "%s [filename] [instructions]"%sys.argv[0]
    sys.exit(1)

filename = sys.argv[1]
lookback = int(sys.argv[2])

if ".exe" in filename:
    m = Module.PE(filename, "x86")
else:
    m = Module.ELF(filename, "x86")

for i in m.find_all_gadgets(lookback):
    print i

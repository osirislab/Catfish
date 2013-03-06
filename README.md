#Catfish
##Introduction
Catfish is a tool used ease the process of finding ROP gadgets and creating payloads with them. It is still under development.

##Usage
Right now, Catfish is somewhat limited. Here is a simple demo of the interactive version that will call MessageBoxA using code from SwDir.dll.

    > load test_bins/swdir.dll
    > static 0
    > static 0x69218BA0
    > static 0x69218C74
    > static 0
    > call MessageBoxA
    > write messagebox.bin
    >

messagebox.bin should now contain a basic payload for launching a MessageBox.

##Prerequisites
All that is needed to run is Distorm (http://code.google.com/p/distorm/)

##Future
Some things planned for the future:

* Make it actually work for more than just simple payloads
* Better support for static values on the stack
* 64-bit support
* Use of instruction decomposition
* Automagic ROP chain generation

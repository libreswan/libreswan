#!/bin/sh

authkey=0x87658765876587658765876587658765

key=0x4142434445464649494a4a4c4c4f4f515152525454575758
# is a key with bad parity in the first subkey.
ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $key --authkey $authkey

key=0x4043434545464649494a4b4c4c4f4f515152525454575758
# is a key with bad parity in the second subkey.
ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $key --authkey $authkey

key=0x4043434545464649494a4a4c4c4f4f515152525454565758
# is a key with bad parity in the third subkey.
ipsec spi --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $key --authkey $authkey




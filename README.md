# rbase64
base64 implementation with optional MIME ASCII table char left rotation (rotl) useful for obfuscation

### Usage
rb64.exe [-d] [-r VALUE] -i INPUT
        -d      decode
        -r      use rotl shifting of ASCII table by VALUE(int) (if omitted, use standard base64 ASCII)
        -i      INPUT to encode/decode

*Inspired by "Practical Malware Analysis" by Michael Sikorski and Andrew Honig*

Tested on win32, Linux, OpenBSD

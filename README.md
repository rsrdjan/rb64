# rbase64
base64 implementation with optional MIME ASCII table char left rotation (rotl) useful for obfuscation

### Usage
```
rb64.exe [-d] [-r VALUE] -i INPUT

-d      decode

-r      use rotl shifting of ASCII table by VALUE(int) (if omitted, use standard base64 ASCII)

-i      INPUT to encode/decode
```
### Examples

Encode - classic base64:
```
rb64.exe -i "Hello world"
```

Encode - base64, rotate table by 4:
```
rb64.exe -r 4 -i "Hello world"
```

Decode - classic base64:
```
rb64.exe -d -i "SGVsbG8gd29ybGQ="
```

Decode - base64, rotate table by 4:
```
rb64.exe -d -r 4 -i "WKZwfKAkh6B2fKU="
```

*Inspired by "Practical Malware Analysis" by Michael Sikorski and Andrew Honig*

Tested on win32, Linux, OpenBSD

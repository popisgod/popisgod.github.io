+++
title = "hash challenge writeup"
date = "2024-02-10"
description = "A writeup to the hash challenge from pwnable.co.il"
tags = [
    "pwn", 
    "pwnable.co.il"
]
categories = [
    "pwn" ,
    "pwnable.co.il"
]
authors = ["popisgod",
            "Ron"]
series = ["pwnable.co.il"]
+++


Looking at the source code of the challenge, we see that the program loads the flag and hashes it.

```c
int fd = open("flag", O_RDONLY);
int bytes = read(fd, &flag_str, 0x100);
...
MD5_Update(&flag, flag_str, bytes);
MD5_Final(flag_hash, &flag);

```

The program then prints the flag hash for us in hexadecimal format.

```c
puts("Flag MD5: ");
for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", flag_hash[i]);
puts("");
```

After that, the user gets to input their guess for the flag, which gets hashed too.

```c
bytes = read(0, guess, bytes);
MD5_CTX guess_ctx;
MD5_Init(&guess_ctx);
MD5_Update(&guess_ctx, guess, bytes);
MD5_Final(guess_hash, &guess_ctx);
```
 
 
And then, the two hashes get compared using the function `strcmp` . If `strcmp` returns equal, the program prints the flag; otherwise, it prints "Wrong!!" and exits.

```c
if (!strcmp(flag_hash, guess_hash)) {
    puts("Congrats!!!");
    puts(flag_str);
} else {
    puts("Wrong!!");
}
return 1;
```

We can immediately see a logical error in the code: the `strcmp` function was used even though the hashes are not strings. The `strcmp` function compares until there's a NULL byte, `00` . This means that if there's a `00` byte in the hash of the flag, the function will return earlier than it should, and it will only check if they're both equal up to that point.

Now going back to the printed hash `537500469ddfc5b29e9379cdcc2f3c86`, we see the third byte is `00` . It means that the hashes will only be compared up to the third byte and that the hashes only need to be equal in the first two bytes for the function to return equal.

Using this newly acquired information on the program, I've created a Python script that brute-forces a 'collision' and creates a hash with the prefix `537500` , equal to the flag hash.

```python
from pwn import * 
import hashlib

def find_md5_with_prefix(prefix):
    i = 0
    while True:
        data = str(i) + '\n'
        
        md5_hash = hashlib.md5(data.encode()).hexdigest()
        
        if md5_hash[:len(prefix)] == prefix:
            return data, md5_hash
        
        i += 1
        
        
if args['LOCAL']:
    io = process('./hash')
else:
    io = remote('pwnable.co.il', 9006)
    
prefix = '537500'
payload, _ = find_md5_with_prefix(prefix)

io.send(payload)
io.interactive()
```

The hash of the payload created by my script was `537500469ddfc5b29e9379cdcc2f3c86` , and as I expected, it passed the equality check and printed out the flag.


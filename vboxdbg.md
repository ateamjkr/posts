### Playing with memory contents using virtualbox debug

#### Preface
I am really curious about how Linux (and BSD) based appliances are built and what protection mechansism are in place to keep the appliances' administrative users from getting root permission. 

Normally, when I have VM based appliances it is quite easy to get access to the OS. Booting into single user mode and adding a secondary root user usually does the trick. Sometimes the disks are LUKS encrypted with the keyfiles or a password that can be read from initrd of initramfs archive. Once the disks are properly decrypted and mounted I can add a secondary root account like before.

#### Encrypted initramfs
This time I was unlucky for my normal steps because the appliance I wanted to analyze had an encrypted initramfs. This is something I have not encountered before and I am still trying to fully understand how it works. Maybe I will write something about it in the future.

Not having easy access to the filesystem made me think and finally I came to the conclusion that once I had access to the memory of the running VM I would be able to gather information how to access the VM. I booted the VM, after some time paused it and analyzed the memory contents from the written memory snapshot. I was able to gather the contents of `/etc/shadow`, some parts of the web application and parts of the appliance's curses menu the admin can use from the Linux console from the cached filesystem. The root password hash did not crack after some time (with several wordlists) so I was still not able to login.

Having memory contents and the cached filesystem at rest I exchanged the password hash from `/etc/shadow` and tried to unpause the VM in virtualbox. Unfortunately virtualbox has some safeguards for snapshot integrity so I could not bring the VM back up. Being lazy (and untalented with C) I did not want to find the checks in the source and recompile virtualbox. After some googling I found an interesting feature of virtualbox: VBoxDbg. 

#### VboxDbg

The VboxDbg feature is disabled by default. It can be enabled by exporting two environment variables before starting up virtualbox GUI:

```
jkr@kali:~$ export VBOX_GUI_DBG_ENABLED=true
jkr@kali:~$ export VBOX_GUI_DBG_AUTO_SHOW=true
jkr@kali:~$ virtualbox &
```

When we start up the VM we are presented with three windows: The standard VM window (with an added `Debug` menu, the VBoxDbg console window as well as a statistics window. The VM starts in paused mode so first it needs to be unpaused. The VBoxDbg console has a command prompt with an integrated help feature:

```
VBoxDbg> help

VirtualBox Debugger Help Summary
--------------------------------

help commands      Show help on all commands.
help functions     Show help on all functions.
help operators     Show help on all operators.
help all           All the above.
help <cmd-pattern> [...]
                   Show details help on individual commands, simple
                   patterns can be used to match several commands.
help [summary]     Displays this message.
```

Looking at the `help all` output I quickly found some interesting commands:

```
(...)
d           [addr]                         Dump memory using last element size and type.
dF          [addr]                         Dump memory as far 16:16.
dFs         [addr]                         Dump memory as far 16:16 with near symbols.
da          [addr]                         Dump memory as ascii string.
db          [addr]                         Dump memory in bytes.
dd          [addr]                         Dump memory in double words.
dds         [addr]                         Dump memory as double words with near symbols.
da          [addr]                         Dump memory as ascii string.
(...)
eb          <addr> <value>                 Write a 1-byte value to memory.
ew          <addr> <value>                 Write a 2-byte value to memory.
ed          <addr> <value>                 Write a 4-byte value to memory.
eq          <addr> <value>                 Write a 8-byte value to memory.
(...)
sa          <range> <pattern>              Search memory for an ascii string.
sb          <range> <pattern>              Search memory for one or more bytes.
sd          <range> <pattern>              Search memory for one or more double words.
sq          <range> <pattern>              Search memory for one or more quad words.
su          <range> <pattern>              Search memory for an unicode string.
sw          <range> <pattern>              Search memory for one or more words.
(...)
```

#### Patching the VM's memory on-the-fly
As I failed with patching the memory at rest I made following plan of action for altering the memory of the running VM:

* Search memory contents for `root:$1$` to find the cached `shadow` file.
* Patch the memory location to password hash for password "root".
* Login as `root`/`root` and see `uid=0` when typing `id` on the prompt :-P

##### Step 1 - Search memory
I was searching for a known string in memory so in VBoxDbg console the command `sa` was used. It searches for an ASCII string in the memory of the virtual machine:

```
VBoxDbg> help sa
sa          <range> <pattern>              Search memory for an ascii string.
             <2+ args>                     
    range        Register to show or set. <1-1>
    pattern      Pattern to search for. <1+>
```

To search for `root:$1$` I used the command `sa 0 "root:$1$"`. This is the output I got:
![Searching Memory](https://github.com/ateamjkr/posts/blob/master/img/vboxdbg-001.png)

The screenshot shows the root hash from `/etc/passwd`. No idea why I saw it multiple times I just focussed on the first address and used one of the memory display commands to check what I had at the address:

```
VBoxDbg> help db
db          [addr]                         Dump memory in bytes.
             <0 to 1 args>                 
    address      Address where to start dumping memory. <optional-1>
```

Using the VBoxDbg command `db 00008800d8cd3000` I could easily verify that I found the beginning of `/etc/shadow`:
![Displaying Memory](https://github.com/ateamjkr/posts/blob/master/img/vboxdbg-002.png)

##### Step 2 - Modify memory
I had the correct address of the cached file in memory so I was ready to replace the contents with some data that suited me better - the hash of the password `root`. To make replacement easier I also used a 7 character salt like I found on the VM so that the length of my password hash and the one configured matched.

```
$ printf root | openssl passwd -1 -stdin -salt abcdefg
$1$abcdefg$UZbUnWKtogzB6U6Hv6fvN/
```

For memory modification there is commands to write 1, 2, 4 or 8 bytes into memory. The password hash string above has 33 characters and unfortunately is not a multiple of 8. But as the password string starts with `$1$` for both strings I could just write from the second character which gave 32 bytes (4*8 bytes) to write. For this I used following command:

```
VBoxDbg> help eq
eq          <addr> <value>                 Write a 8-byte value to memory.
             <2 args>                      
    address      Address where to write. <1-1>
    value        Value to write. <1+>
```

Experienced HTB and CTF player I am I knew that CyberChef can help me to quickly convert stuff into other stuff. I just used following recipe:

* To Hex
* Swap engianess (Data format: Hex, Word length: 8 bytes)
* Remove whitespace

This converted my 32 character string `1$abcdefg$UZbUnWKtogzB6U6Hv6fvN/` into following byte sequence:

```
6665646362612431576e55625a5524675536427a676f744b2f4e766636764836
```

Splitting it up into four 8 byte chunks I planned to use following four commands to alter the memory:

```
eq <addr> 6665646362612431
eq <addr+8> 576e55625a552467
eq <addr+16> 5536427a676f744b
eq <addr+24> 2f4e766636764836
```

As the beginning of `/etc/shadow` was at `00008800d8cd3000` I just used `bc` to calculate the needed addresses:

```
$ bc -q
obase=16
ibase=16
00008800D8CD3000
8800D8CD3000
.+6 
8800D8CD3006
.+8 
8800D8CD300E
.+8 
8800D8CD3016
.+8
8800D8CD301E
```

I finally had to run following commands to get my password into the memory and verified the contents of `/etc/shadow` once again:

```
eq 00008800d8cd3006 6665646362612431
eq 00008800d8cd300e 576e55625a552467
eq 00008800d8cd3016 5536427a676f744b
eq 00008800d8cd301e 2f4e766636764836
db 00008800d8cd3000
```

This is what I got:

![Modifying Memory](https://github.com/ateamjkr/posts/blob/master/img/vboxdbg-003.png)

##### Step 3 - Getting the root flag ;)
The final step was to verify the patching was correct. I could log in with `root`/`root` and ran `id` and got my favorite output for this command: `uid=0(root)`. 

![Get root flag](https://github.com/ateamjkr/posts/blob/master/img/vboxdbg-004.png)

#### The end
Once on the box I quickly discovered a hand full of vulnerabilites that from then on helped me to get root without touching VBoxDbg at all.

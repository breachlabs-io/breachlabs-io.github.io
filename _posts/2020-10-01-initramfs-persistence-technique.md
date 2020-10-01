---
title: Initramfs Persistence Technique
published: true
---

You may have never heard of initramfs, but you have definitely seen it. Every time you boot up a Linux machine, you see a flash of text which is the initramfs telling you what it is doing. It is a crucial part of the boot process, and without it you would never get to see your precious terminal. Before we get into some of the malicious things we can do with the initramfs, lets learn a little bit about its role in the boot process.

### The Linux Boot Process

At a high level, when you press the power button this is what happens:

- The BIOS starts up and looks for the bootloader (usually GRUB for Linux) in the first 512 bytes of the primary HDD, loads it into memory, and jumps to it.
- GRUB is a multi-stage bootloader, so it loads the rest of itself into memory and continues execution. GRUB will do some initial scanning of the system, and setup the environment before loading the kernel and jumping to it. Wonder where the kernel is loaded from? Look in the `/boot` directory, you'll find it there with the name `vmlinuz`.
- After some more setup, the kernel will decompress and mount the initramfs (Initial RAM Filesystem) as a RAM disk. The `initrd.img` file in the `/boot` directory is the initramfs.
- The kernel executes the `init` script that is part of the initramfs filesystem. This loads several kernel modules needed to mount the host filesystem (i.e. ext4). Then it kicks off some scripts that mounts the hosts root filesystem, `chroot`'s to it, and calls the hosts `init` script. Which in turn starts all of the services needed for the usability of the operating system.

### Initramfs Structure

Below is the extracted contents of the `initrd.img` file.

```
user@kali:~/Demo/extract/main$ ls -l
total 36
lrwxrwxrwx  1 root root    7 Sep 23 17:29 bin -> usr/bin
drwxr-xr-x  3 root root 4096 Sep 23 17:29 conf
drwxr-xr-x  2 root root 4096 Sep 23 17:29 cryptroot
drwxr-xr-x  8 root root 4096 Sep 23 17:29 etc
-rwxr-xr-x  1 root root 6454 Sep 24 09:46 init
lrwxrwxrwx  1 root root    7 Sep 23 17:29 lib -> usr/lib
lrwxrwxrwx  1 root root    9 Sep 23 17:29 lib32 -> usr/lib32
lrwxrwxrwx  1 root root    9 Sep 23 17:29 lib64 -> usr/lib64
lrwxrwxrwx  1 root root   10 Sep 23 17:29 libx32 -> usr/libx32
drwxr-xr-x  2 root root 4096 Jun 21 12:47 run
lrwxrwxrwx  1 root root    8 Sep 23 17:29 sbin -> usr/sbin
drwxr-xr-x 10 root root 4096 Sep 23 17:33 scripts
drwxr-xr-x 10 root root 4096 Sep 23 17:29 usr
drwxr-xr-x  3 root root 4096 Sep 23 17:29 var
```

As you will probably notice, this looks strikingly similar to the filesystem structure you will see in Linux. That is because this is a trimmed down version of the operating system, with the sole purpose of getting the root partition mounted and kicking off the init of the real operating system. Note that the term "operating system" is used loosely here as the kernel makes up a large portion of it. However, we are only talking about the portion of the operating system that resides on the root partition (i.e. mostly user-land applications).

### Persistence Time!

Alright so how do we use this as a persistence mechanism? Well the `init` script in the initramfs does something important. It mounts the root partition. Given that the script is running with root permissions, this means we can do anything in the root partition before any user-land applications have even started (like any security applications). You could do things like manually adding a user into the `/etc/shadow` file, or adding malware to the system and having it launch with a systemd script.

Lets do an example on a 2020 Kali system. I'm just going to start off by saying that this isn't all that simple, and requires some additional tools to make it work. First you will need `initramfs-tools`: `sudo apt install initramfs-tools` (this may already be installed). Next you will need `binwalk`: `sudo apt install binwalk`. Run `binwalk /boot/initrd.img` (this might be located in the `/` directory instead of `/boot`). The output from `binwalk` should look something like this:

```
user@kali:~$ binwalk /initrd.img

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ASCII cpio archive (SVR4 with no CRC), file name: "kernel", file name length: "0x00000007", file size: "0x00000000"
120           0x78            ASCII cpio archive (SVR4 with no CRC), file name: "kernel/x86", file name length: "0x0000000B", file size: "0x00000000"
244           0xF4            ASCII cpio archive (SVR4 with no CRC), file name: "kernel/x86/microcode", file name length: "0x00000015", file size: "0x00000000"
376           0x178           ASCII cpio archive (SVR4 with no CRC), file name: "kernel/x86/microcode/.enuineIntel.align.0123456789abc", file name length: "0x00000036", file size: "0x00000000"
540           0x21C           ASCII cpio archive (SVR4 with no CRC), file name: "kernel/x86/microcode/GenuineIntel.bin", file name length: "0x00000026", file size: "0x002DD400"
3004080       0x2DD6B0        ASCII cpio archive (SVR4 with no CRC), file name: "TRAILER!!!", file name length: "0x0000000B", file size: "0x00000000"
3004416       0x2DD800        gzip compressed data, from Unix, last modified: 1970-01-01 00:00:00 (null date)
44913745      0x2AD5451       MySQL MISAM compressed data file Version 5
44913784      0x2AD5478       MySQL MISAM compressed data file Version 5
44913823      0x2AD549F       MySQL MISAM compressed data file Version 5
44913862      0x2AD54C6       MySQL MISAM compressed data file Version 5
44913901      0x2AD54ED       MySQL MISAM compressed data file Version 5
```

The important thing to note here is that there is a cpio archive containing microcode for the CPU, and a gzipped cpio archive containing the mini Linux filesystem (the MySQL stuff is part of the gzipped cpio archive that has been misidentified by binwalk). The end of the first cpio archive is marked by the file name "TRAILER!!!". Remember this... it is important. Now why are we going through all of this? Well... we have a tool, `unmkinitramfs`, that can extract the contents of both of the archives in the `initrd.img` file. However, we don't have an equivalent tool to reconstruct the `initrd.img`. So instead we have to break out the first cpio archive containing the microcode, rebuild the second archive (using `cpio` and `gzip`) after we have inserted whatever malicious code we want, and then smush it all back together. Told you it wasn't that simple! Lets go through the process now.

**Note**: Make sure you're doing this in a virtual machine, and have created a snapshot!

1. Copy `/boot/initrd.img` (or `/initrd.img`) into its own directory.
2. Using the `binwalk` output, find the last occurrence of "TRAILER!!!", and take note of the decimal value (in the example output above it is 3004080). It is possible to have several cpio archives before the gzip compressed cpio archive.
3. From this point forward, make sure you are in the directory where you copied the `initrd.img` file to. Run `dd if=initrd.img of=initrd.img-begin count=3004080 bs=1` (replacing the count value with the decimal value you recorded in the last step). This will save the first cpio archive for later use.
4. Run `unmkinitramfs initrd.img extracted`. This will unpack the initramfs image into a new directory called `extracted`.
5. Run `cd extracted/main/` to enter the initramfs mini Linux filesystem directory.
6. Open the `init` script in your favorite text editor. Near the bottom you should see something like `maybe_break init`. You want to insert your malicious code before this.
7. For our example, we are adding:
```
# Keep adding hacked to root directory
mount -o remount,rw ${rootmnt}
echo "Yarr've been pwnd" > ${rootmnt}/hacked
```
The remount of the root partition as `rw` is very important. It may be mounted read-only, and if so your malicious code will fail. Save and exit the file.
8. Run `find . | LC_ALL=C sort | cpio -R 0:0 -o -H newc | gzip >> ../../initrd.img-end`. This will create the gzipped cpio archive from the contents in `extracted/main/`.
9. `cd ../../` back to the main directory we were in. Run `cat initrd.img-begin initrd.img-end > initrd.img-new`. That is it now we have a new initramfs image!
10. The `/initrd.img` file is a symlink. We need to replace the linked file. Run `file /initrd.img` to find the linked image location, and replace it with the new one (keep the original file name, **NOT** `initrd.img-new`).
11. Reboot and pray.

### Testing

If all went well, the machine should have rebooted successfully. Login and check the `/` directory. You should see a file called `hacked` with the contents `Yarr've been pwnd`. Delete this file and reboot again. You will see that the file comes back each time... aka persistence.

Hope you had fun, and learned a thing or two!!!

# cub3 (cube-three) 
<hr>
Typically, magic strings and magic GIDs are used to hide LD_PRELOAD rootkit files, but both of those methods are flawed.</br>
GID protection is flawed as, usually, the magic GID can actually be bruteforced. An example way of doing this is by calling chown() in a repeating loop with a forever incrementing GID until the chown() function returns -1 (and/or an error number).</br>
Magic strings are over convoluted and require a tad more programming if used, but it mostly comes down to the programmer of the malware screwing up when it comes to logic-type situations. They're generally just worse than GID protections.</br></br>
So here I am! Providing a PoC work around for both inconveniences. </br>
<i>cub3</i> uses extended attributes (xattr) to protect its files.</br>
xattr is supported by the ext2, ext3, ext4, JFS, Squashfs, Yaffs2, ReiserFS, XFS, Btrfs, OrangeFS, Lustre, OCFS2 1.6 and F2FS file systems in Linux. If you're trying to install <i>cub3</i> on an unsupported file system, that's your fault for being on a box with a terrible file system.</br>
You can easily adapt this to be much better. Improvements can be made, such as using a random magic xattr string.</br></br>
As far as process hiding goes, you can still use GID protections for process hiding, but ONLY for process hiding. You can't use xattr protection for process hiding as the procfs (the file system used by /proc/) doesn't support extended attributes.</br>
Extended attributes can also be disabled in the kernel, too.</br>
<a href="http://pastebin.com/rZvjDzFK">http://pastebin.com/rZvjDzFK</a> is an example GID bruteforcer.</br></br>

## installation instructions

<b>DO NOT TOUCH CONFIG.H. INSTALL.SH HANDLES THIS FILE.</b></br>
</br>
```
git clone https://github.com/x-0rd/cub3.git
cd cub3
./install.sh
```
</br></br>
After installation, the installation script will tell you how to remove cub3 once you're done with it. In case you're a baby, here's how you do it. <b>MAKE SURE YOU'RE ROOT FIRST.</b></br>
```
export DEFAULT_ENV=1
chattr -ia /etc/ld.so.preload
rm -rf /etc/ld.so.preload /lib/cub3.so
```
</br></br><b>Done.</b></br></br>
I added a small feature to allow you to dynamically hide/unhide files/directories. To access this feature, <b>make sure you're in a root shell</b> and export your environment variable. Then type `./hide <your execve pass>` and you'll be shown usage instructions. To unhide files, just change hide to unhide. It's that simple.</br>
This function is handled by the execve() call.</br></br>
## disclaimer & misc information
<ul>
<li type="square">cub3 is not supposed to be used as a rootkit. It has no backdoor functionality, and does nothing malicious on its own. You are given means to remove it easily.</li>
<li type="square">In no way does cub3 try to hide itself. You can still see that the shared object is being loaded by /proc/self/[s]maps, ldd output, LD environment variables, ltrace, dlsym address comparisons/verifications, dlinfo output - general libdl tricks.</li>
<li type="square">There's a setting in config.h you may want to enable. The "DEBUG" constant is set by default to off, if you enable it, you'll see output from every hooked libc function.</li>
<li type="square">I'm lazy and didn't hook any of the stat functions. I didn't deem it necessary.</li>
<li type="square">I'm not responsible for what you do with what I'm giving you.</li>
</ul>
## list of hooked libc functions
<ul>
<li type="square">listxattr, llistxattr, flistxattr</li>
<li type="square">getxattr, lgetxattr, fgetxattr</li>
<li type="square">setxattr, lsetxattr, fsetxattr</li>
<li type="square">removexattr, lremovexattr, fremovexattr</li>
<li type="square">open, open64, openat, creat</li>
<li type="square">unlink, unlinkat, rmdir</li>
<li type="square">symlink, symlinkat</li>
<li type="square">mkdir, mkdirat, chdir, fchdir, opendir, opendir64, fdopendir, readdir, readdir64</li>
<li type="square">execve</li>
</ul>
## contact
<b>Email:</b> xor@cock.lu

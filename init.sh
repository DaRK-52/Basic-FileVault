#!/bin/bash
vp_file=".vault.path"
passwd_md5_file=".passwd.md5"

cd ~
touch $vp_file
# default vault path is ~/secret
echo `pwd`/secret > $vp_file
mkdir `pwd`/secret
touch `pwd`/secret/$passwd_md5_file
# default key is 123456
echo -n "e10adc3949ba59abbe56e057f20f883e"> `pwd`/secret/$passwd_md5_file
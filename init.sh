#!/bin/bash
vp_file=".vault.path"
passwd_md5_file=".passwd.md5"

touch $HOME/$vp_file
# default vault path is ~/secret
echo $HOME/secret > $HOME/$vp_file
mkdir $HOME/secret
touch $HOME/secret/$passwd_md5_file
# default key is 123456
echo -n "e10adc3949ba59abbe56e057f20f883e"> $HOME/secret/$passwd_md5_file
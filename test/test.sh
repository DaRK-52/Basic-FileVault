#!/bin/bash
kmod_path="/home/zhuwenjun/system_software/code/kernel"
kmod_name="basic_filevault.ko"
umod_path="/home/zhuwenjun/system_software/code/usr"
vault_apath="/home/zhuwenjun/secret"
vault_rpath="secret"
file_path="$vault_apath/flag"

start_test(){
    cd ${kmod_path}
    insmod ${kmod_name}
}

unlock_vault(){
    cd ${umod_path}
    ./vault_manager 123456
}

check_dir(){
    if [[ "`pwd`" != "${vault_apath}" ]];
    then
        echo "Chdir Failed!"
    else
        echo "Chdir Success!"
    fi
}

check_mkdir(){
    if [[! -d "${vault_apath}/dir"]];
    then
        echo "Mkdir Success!"
    else
        echo "Mkdir Failed!"
}

check_unlink(){
    if [[! -d "${vault_apath}/unlink_file1"]];
    then
        echo "Unlink Failed!"
    else
        echo "Unlink Success!"
}

check_rename(){
    if [[! -d "${vault_apath}/rename_file2"]];
    then
        echo "Rename Success!"
    else
        echo "Rename Failed!"
}

test_chdir(){
    cd ${vault_apath}
    check_dir
    cd ~
    cd ${vault_rpath}
    check_dir
    unlock_vault
    cd ${vault_apath}
    check_dir
    cd ~
    cd ${vault_rpath}
    check_dir
}

test_open(){
    cat ${file_path}
    unlock_vault
    cd ${vault_apath}
    cat ${file_path}
}

test_mkdir(){
	mkdir "${vault_apath}/dir"
    unlock_vault
    mkdir "${vault_apath}/dir"
    check_mkdir
    rm -rf "${vault_apath}/dir"
}

test_unlink(){
	rm "${vault_apath}/unlink_file1"
    unlock_vault
    rm "${vault_apath}/unlink_file1"
    check_unlink
}

test_rename(){
	mv "${vault_apath}/rename_file1" "${vault_apath}/rename_file2"
    check_rename
    unlock_vault 
    mv "${vault_apath}/rename_file1" "${vault_apath}/rename_file2"
    check_rename
}

end_test(){
    rmmod ${kmod_name}
}

start_test
test_chdir
end_test

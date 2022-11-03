#!/bin/bash
kmod_path="/home/zhuwenjun/system_software/code/kernel"
kmod_name="basic_filevault.ko"
umod_path="/home/zhuwenjun/system_software/code/usr"
vault_apath="/home/zhuwenjun/secret"
vault_rpath="secret"

start_test(){
    cd ${kmod_path}
    echo `pwd`
    insmod ${kmod_name}
}

check_dir(){
    echo `pwd`
    if [[ "`pwd`" != "${vault_apath}" ]];
    then
        echo "Chdir Failed!"
    else
        echo "Chdir Success!"
    fi
}

test_chdir(){
    cd ${vault_apath}
    check_dir
    cd ~
    cd ${vault_rpath}
    check_dir
    cd ${umod_path}
    ./vaultkey
    cd ${vault_apath}
    check_dir
    cd ~
    cd ${vault_rpath}
    check_dir
}

test_open(){

}

test_mkdir(){

}

test_unlink(){

}

test_rename(){
    
}

end_test(){
    rmmod ${kmod_name}
}

start_test
test_chdir
end_test
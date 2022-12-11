# Basic filevault
项目完成了基于系统调用重载的基本型文件保险箱。

## 项目使用
使用以下命令即可加载模块
```shell=
git clone git@github.com:DaRK-52/Basic-FileVault.git

cd Basic-FileVault

sudo bash init.sh

cd kernel

make

sudo insmod basic_filevault.ko
```
卸载模块命令如下
```shell=
chmod 777 stop.sh

sudo bash stop.sh
```
使用保险箱管理程序来解锁保险箱或是修改保险箱路径和修改密码(**默认密码123456**)，vault_manager具体使用可以输入h查看
```shell=
// under the directory of Basic-FileVault
cd usr

make

./vault_manager
```

保险箱默认路径为`~/secret`，未经授权的用户无法访问保险箱内的内容，解锁有效期暂定20s。
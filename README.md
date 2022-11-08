# Basic filevault
项目完成了基于系统调用重载的基本型文件保险箱。

## 项目使用
使用以下命令即可加载模块
```shell=
git clone git@github.com:DaRK-52/Basic-FileVault.git
cd Basic-FileVault
sudo bash init.sh
```
卸载模块命令如下
```shell=
chmod 777 stop.sh
sudo bash stop.sh
```
保险箱默认路径为`~/secret`，未经授权的用户无法访问保险箱内的内容，可以使用`usr/vault_manager`输入密码解锁（默认密码`123456`），有效期暂定20s。
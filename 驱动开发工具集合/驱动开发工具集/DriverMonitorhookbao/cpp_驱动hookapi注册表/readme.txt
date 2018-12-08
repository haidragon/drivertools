1  为输出文件
2  为过滤文件
×.sys通过monitor导入到xp然后go
就会发生hook  注册表被hook了
在脱离驱动时候注册表恢复hook会恢复
1  记录了那些操作了注册表以及注册表的路径
ssdt_hook.cpp   提供两个接口实现hook
driver.cpp          提供驱动的入口以及提供写文件读文件的接口函数以及打印的接口
看打印用debugview

createfile_查看dll函数名字提供了如何解析dll文件pe在内存的镜像
dllspec.C   指出了dll函数在进程中的镜像

dll pe在内存的镜像   dll是pe在内存的完全镜像，但是导入的时候会修改内部的一些值参数以他和原来保存在磁盘的没什么不同
getdllfunctionaddrress是干同样活

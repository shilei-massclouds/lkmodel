#!/bin/bash

rm -f ./hello1
rm -f ./hello2
rm -f ../apps.bin

# 编译
riscv64-linux-gnu-gcc -static ./main1.c -o hello1
riscv64-linux-gnu-strip ./hello1
riscv64-linux-gnu-gcc -static ./main2.c -o hello2
riscv64-linux-gnu-strip ./hello2



# 打包
APP_OUT=../apps.bin
MAGIC_NUM='\xAB\xCD'
MAGIC_LEN=2
# 定义应用程序列表
# APP_LIST=("app_nop.bin" "app_wfi.bin" "app_ebreak.bin")
# APP_LIST=("app_nop.bin" "app_wfi.bin")
APP_LIST=("hello1" "hello2")
OFF_SET=0

# 生成空文件
rm -rf ${APP_OUT}
dd if=/dev/zero of=${APP_OUT} bs=1M count=32  conv=notrunc > /dev/null 2>&1


# 文件格式
# 字节序大端法
# 2字节魔数 ABCD
# 2字节长度
# 文件内容

# 遍历应用程序列表并打印每个元素及其索引位置
for ((i = 0; i < ${#APP_LIST[@]}; i++)); do

    APP=${APP_LIST[i]}
    # 生成文件大小和文件内容的元数据
    APP_SIZE=$(stat -c %s ${APP})
    APP_SIZE_HEX=$(printf "%04X" $APP_SIZE)
    echo "======================================"
    echo "Index: $i, App: ${APP}, OFF_SET: $OFF_SET " 'APP_SIZE:'${APP_SIZE} , 'APP_SIZE_HEX:'${APP_SIZE_HEX}
    echo 'CONTENT:'
    xxd -ps -u  -s 0 -l 20  -c 10  $APP

    # 写入魔数0xABCD
    printf $MAGIC_NUM | dd of=${APP_OUT} bs=1 count=2 seek=$OFF_SET  conv=notrunc  > /dev/null 2>&1
    OFF_SET=$((OFF_SET + MAGIC_LEN ))

    # 将文件长度以大端字节序写入到 ,长度为2字节
    printf "\x${APP_SIZE_HEX:0:2}\x${APP_SIZE_HEX:2:2}" | dd bs=1 of=${APP_OUT} conv=notrunc seek=$OFF_SET > /dev/null 2>&1
    OFF_SET=$((OFF_SET + 2 ))
    
    # 写入内容
    dd if=${APP} of=${APP_OUT} bs=1 conv=notrunc seek=$OFF_SET > /dev/null 2>&1
    

    OFF_SET=$((OFF_SET + APP_SIZE ))
   
done


echo "================================"
echo "apps.bin content:"

# -p 或 --ps：将输出结果以连续hexdump的方式显示，不会显示偏移量或原始的字符数据。
# -r 或 --revert：从hex dump反向到二进制。
# -s <offset> 或 --seek <offset>：从指定的偏移量开始进行操作。
#-l <len> 或 --len <len>：只处理指定长度的输入数据。
# -c <cols> 或 --cols <cols>：设置每行显示的列数
# -u 十六进制输出时使用大写字母，默认是小写字母
# -g bytes    number of octets per group in normal output. Default 2 (-e: 4).
xxd -ps -u  -s 0 -l 100  -c 2  $APP_OUT


# 这会输出以下内容
:<<=====


======================================
Index: 0, App: app_wfi.bin, OFF_SET: 0  APP_SIZE:6 , APP_SIZE_HEX:0006
CONTENT:
730050100000
======================================
Index: 1, App: app_ebreak.bin, OFF_SET: 10  APP_SIZE:4 , APP_SIZE_HEX:0004
CONTENT:
02900000
================================
apps.bin content:
ABCD
0600
7300
5010
0000
ABCD
0400
0290
0000


=====
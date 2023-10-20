#make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- vexpress_defconfig O=../objects/vexpress-v2p-ca9
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- menuconfig O=../objects/vexpress-v2p-ca9
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -j12 O=../objects/vexpress-v2p-ca9
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- LOADADDR=0x60003000 uImage -j12 O=../objects/vexpress-v2p-ca9

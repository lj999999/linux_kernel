#make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- vexpress_defconfig O=../objects/vexpress-v2p-ca9-arm64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- menuconfig O=../objects/vexpress-v2p-ca9-arm64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j12 O=../objects/vexpress-v2p-ca9-arm64
#make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LOADADDR=0x60003000 uImage -j12 O=../objects/vexpress-v2p-ca9-arm64

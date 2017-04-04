# Onlive Firmware v1.0

## Contents
 - `Microconsole/onlive.dmp`
    - Contents of the Samsung K9F2G08U0B NAND Flash

## Notes

 - Use `extract.sh` to extract the compressed firmware file.
 - This seems to be a 2010 version of the Steam Link - https://github.com/ValveSoftware/steamlink-sdk
 - There's a lot of references to GPLv2 within the image, so this repo is licensed under GPLv2.

### Environment

 - **CPU**: Marvell 88DE3010 ARMv5 (Little Endian)
 - **Memory**: 4x1GB DDR2 ELPIDA E1116AEBG
 - **Storage**: Samsung 2GB NAND Flash [K9F2G08U0B]
 - **Bootloader**: U-Boot
 - **Linux Kernel Version**: 2.6.27.39
 - **File System Type**: YAFFS2

### Hashes

```
---shadow---
root:$1$$wQCY2EFvsLKFoVcT1e0Kq0:12215:0:99999:7:::
sshd:!:0:0:99999:7:::
ratio:$1$$Ox3sD7SU2sKjDwBMqX2/b0:12215:0:99999:7:::
system:$1$$SPGJYr/enc6gAZU73WtZw/:12215:0:99999:7:::

---shadow---
root:$1$w25wunDK$afkqwthNX7R1yWZzJCrsG.:12215:0:99999:7:::


---passwd---
root:x:0:0:root:/home:/bin/sh
ftp:x:11:101:ftp user:/home:/bin/false
www:x:12:102:www user:/home:/bin/false
sshd:x:100:65534:SSH Server:/var/run/sshd:/bin/false
messagebus:x:103:104:messagebus:/dev/null:/bin/false
rpcuser:x:65533:65534:RPC user:/dev/null:/bin/false
nobody:x:65534:65534:Unprivileged Nobody:/dev/null:/bin/false
```

### TODO
 - Extract firmware from the controller.
 - See if it's possible to transform an Onlive Microconsole into a [Steamlink](https://www.youtube.com/watch?v=uOa-ObWPAKg).
# APKProxyHelper

APKProxyHelper paches an apk for proxying.

Usage
----------

```
$ python3 aph.py -h               
usage: APKProxyHelper [-h] --apk APK

optional arguments:
  -h, --help            show this help message and exit
  --apk APK, -a APK     The path to the apk file
```

Output
----------

```
$ python3 aph.py -a apk.apk
[*] Decompiling apk.apk
.....
[*] Adding network file to apk/res/xml
[*] Updating manifest at apk/AndroidManifest.xml
[*] Repackaging to apk_proxy.apk
......
[*] Re-signing apk apk_proxy.apk
.....
[*] Cleaning up directory apk
```

Useful Notes
----------

1. To fix `brut.androlib.AndrolibException: brut.common.BrutException`, delete existing resource table.
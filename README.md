libnss-default-gw
==============

The libnss-default-gw name service switch module resolves the name
"gw.localhost" to the IP address of the gateway of the currently configured default route.

install
--------------

```
$ make  
$ sudo make install
```

setup
--------------

```
$ sudo sed -i -re 's/^(hosts: .*files)(.*)$/\1 default_gw\2/' /etc/nsswitch.conf
```

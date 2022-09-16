# Install libxdp headers
```shell
 git clone https://github.com/xdp-project/xdp-tools.git
 cd xdp-tools
 sudo make install
```

# Install libbpf headers
```shell
 git clone https://github.com/libbpf/libbpf.git
 cd libbpf/
 cd src/
 sudo BUILD_STATIC_ONLY=y  make install
```

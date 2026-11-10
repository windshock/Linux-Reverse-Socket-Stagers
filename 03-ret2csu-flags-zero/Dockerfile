# Reproducible x86_64 lab for the ret2csu + flags=0 demo.
#
# Built on Ubuntu 20.04 (glibc 2.31) ON PURPOSE: it still ships
# __libc_csu_init, which the ret2csu gadget lives in. glibc >= 2.34
# (Ubuntu 22.04+) removed it, so ret2csu is not available there.
#
# On Apple Silicon: `colima start --arch x86_64` first.
FROM --platform=linux/amd64 ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev python3 python3-dev python3-pip binutils file gdb && \
    pip3 install --no-cache-dir pwntools && \
    rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir bitarray==3.0.0 && \
    pip3 install --no-cache-dir 'https://github.com/windshock/ropbot/archive/refs/heads/feat/ret2csu-chain-builder.tar.gz#subdirectory=ropbot'

WORKDIR /work
COPY src/ /work/src/
COPY exploit/ /work/exploit/
RUN make -C src && cp src/vuln_client3 /work/vuln_client3 && file /work/vuln_client3

CMD ["/bin/bash"]

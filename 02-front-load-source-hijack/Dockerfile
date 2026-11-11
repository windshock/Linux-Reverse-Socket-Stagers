# Reproducible x86_64 lab for the front-load source-hijack demo.
# On Apple Silicon: `colima start --arch x86_64` first.
FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev python3 python3-pip binutils file gdb && \
    pip3 install --no-cache-dir pwntools angr angrop && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY src/ /work/src/
COPY exploit/ /work/exploit/
RUN make -C src && cp src/vuln_client2 /work/vuln_client2 && file /work/vuln_client2

CMD ["/bin/bash"]

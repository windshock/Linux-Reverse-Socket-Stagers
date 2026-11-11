# Reproducible x86_64 lab for the single-socket reverse-staging demo.
#
# On Apple Silicon / arm64 hosts, start an x86_64 VM first so the planted
# gadgets and ret2libc match the ABI, e.g.:
#     colima start --arch x86_64 --cpu 2 --memory 4
#
# Build & run via ../run.sh (needs --privileged to toggle ASLR from inside).
FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev python3 python3-pip binutils file gdb && \
    pip3 install --no-cache-dir pwntools angr angrop && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY src/ /work/src/
COPY exploit/ /work/exploit/

RUN make -C src && cp src/vuln_client /work/vuln_client && file /work/vuln_client

CMD ["/bin/bash"]

# Probe image for the CVE-2026-121810 lab: the pinned stdlib python base
# (same digest as the root lab's probe, TOFU 2026-11-19) plus a
# version-pinned aioquic for the QUIC/H3 client. The pin is the pip
# version (aioquic 1.2.0, resolved over HTTPS from PyPI, 2026-11-19) —
# pip itself verifies package integrity on install.
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

RUN pip install --no-cache-dir aioquic==1.2.0

WORKDIR /poc
CMD ["sleep", "infinity"]

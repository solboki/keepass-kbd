#!/usr/bin/env python3
"""Génère un catalogue Qt .qm (messages par identifiant, pour qsTrId) sans lrelease.
   mkqm.py sortie.qm identifiant=traduction [...]"""
import struct, sys

MAGIC = bytes.fromhex("3CB86418CAEF9C95CD211CBF60A1BDDD")
TAG_END, TAG_TRANSLATION, TAG_SOURCE = 1, 3, 6
HASHES, MESSAGES = 0x42, 0x69

def elf_hash(data: bytes) -> int:
    h = 0
    for c in data:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h or 1

def build(pairs):
    messages, hashes = b"", []
    for ident, text in pairs:
        src = ident.encode("utf-8")
        tr = text.encode("utf-16-be")
        hashes.append((elf_hash(src), len(messages)))
        messages += bytes([TAG_TRANSLATION]) + struct.pack(">I", len(tr)) + tr
        messages += bytes([TAG_SOURCE]) + struct.pack(">I", len(src)) + src
        messages += bytes([TAG_END])
    hashes.sort()
    hblock = b"".join(struct.pack(">II", h, o) for h, o in hashes)
    return (MAGIC + bytes([HASHES]) + struct.pack(">I", len(hblock)) + hblock
            + bytes([MESSAGES]) + struct.pack(">I", len(messages)) + messages)

if __name__ == "__main__":
    out = sys.argv[1]
    pairs = [a.split("=", 1) for a in sys.argv[2:]]
    open(out, "wb").write(build(pairs))

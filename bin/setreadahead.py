#!/usr/bin/env python3
import os

MOUNTINFO_FILE = "/proc/self/mountinfo"
import sys

try:
    mount_point = sys.argv[1].rstrip("/")
except IndexError:
    msg = "Usage: %s /mount/point" % sys.argv[0]
    print(msg)
    sys.exit(1)

try:
    readahead_kbs = sys.argv[2]
except IndexError:
    readahead_kbs = 10240

try:
    readahead_kbs = int(readahead_kbs)
except TypeError:
    msg = "Readahead kbs must be int."
    print(msg)
    sys.exit(1)

fd = open(MOUNTINFO_FILE, "r")
file_data = fd.read()
fd.close()

def main():
    readahead_set = False
    for line in file_data.split("\n"):
        data = line.split()
        if not data:
            continue
        bdi_id = data[2]
        mnt = data[4].rstrip("/")
        if mnt != mount_point:
            continue
        fs_type = data[9]
        if not fs_type.startswith("OTPmeFS:/"):
            msg = "Will not set readahead_kbs for non-OTPmeFS mount."
            print(msg)
            sys.exit(1)
        readahead_set = True
        bdi_file = "/sys/class/bdi/%s/read_ahead_kb" % bdi_id
        fd =  open(bdi_file, "w")
        fd.write(str(readahead_kbs))
        fd.close()

    if not readahead_set:
        msg = "Unknown OTPmeFs mount: %s" % mount_point
        print(msg)
        sys.exit(1)

if __name__ == '__main__':
    main()

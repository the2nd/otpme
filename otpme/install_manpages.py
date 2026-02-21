#!/usr/bin/env python3
"""Install OTPme manpages to /usr/local/share/man/."""
import os
import sys
import glob
import shutil


def main():
    man_dir = os.path.join(os.path.dirname(__file__), "man")
    if not os.path.isdir(man_dir):
        print("Error: manpage source directory not found: %s" % man_dir, file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1:
        dest_base = sys.argv[1]
    else:
        dest_base = "/usr/local/share/man"
    if not os.path.isdir(os.path.dirname(dest_base)):
        print("Error: %s does not exist." % os.path.dirname(dest_base), file=sys.stderr)
        sys.exit(1)

    installed = 0
    for dest, pattern in [("man1", "*.1"), ("man7", "*.7"), ("man5", "*.5")]:
        pages = glob.glob(os.path.join(man_dir, pattern))
        if not pages:
            continue
        dest_dir = os.path.join(dest_base, dest)
        os.makedirs(dest_dir, exist_ok=True)
        for page in pages:
            shutil.copy2(page, dest_dir)
            installed += 1

    print("Installed %d manpages to %s." % (installed, dest_base))


if __name__ == "__main__":
    main()

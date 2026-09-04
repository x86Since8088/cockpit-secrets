"""Create ONE throwaway KDBX database for the root verification suite.

    mkdb.py <path> <passphrase-file> <label>

Deliberately built with `pykeepass` directly rather than through a backend:
the point of the suite is to hand the helper a database it did not write, so
using the helper to make its own subject would be the round-trip fallacy
docs/KNOWN_ISSUES.md I19 warns about, one level down.

The passphrase is read from a 0600 file and handed to `create_database` as a
keyword argument inside this process. It never reaches argv - only the PATH to
the file does - and it is never printed.

The file is created 0600 before anything is written into it, with O_EXCL:
the safe must not be readable by anyone for even the instant between creation
and chmod, and it must never silently overwrite a database that is already
there.
"""
import os
import sys

from pykeepass import create_database


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    path, pwfile, label = sys.argv[1], sys.argv[2], sys.argv[3]

    st = os.stat(pwfile)
    if st.st_mode & 0o077:
        raise SystemExit("passphrase file %s is not 0600" % pwfile)
    with open(pwfile) as fh:
        password = fh.read().rstrip("\n")

    if os.path.exists(path):
        raise SystemExit("refusing to overwrite an existing safe: %s" % path)

    # Stake the name at 0600 first. create_database() opens by name with the
    # process umask, and a safe that exists at 0644 for a millisecond is a safe
    # that was readable by adversary A1 for a millisecond.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)

    kp = create_database(path, password=password)
    group = kp.add_group(kp.root_group, "Throwaway")
    kp.add_entry(group, "seed-entry", "seed-user", "seed-not-a-real-secret",
                 url="https://throwaway.invalid",
                 notes="created by tests/root for %s; delete with 90-cleanup.sh"
                      % label)
    kp.save()
    os.chmod(path, 0o600)

    # Only the shape, never the contents.
    print("     created %s (%d bytes, mode 0%o, %d entries, %d groups)"
          % (path, os.path.getsize(path), os.stat(path).st_mode & 0o777,
             len(kp.entries), len(kp.groups)))


if __name__ == "__main__":
    main()

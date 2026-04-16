# Applying the persistent AFL harness on non-SVN httpd sources (e.g. 2.4.17 tarball)

If your `httpd` source was extracted from a release tarball (not checked out via `svn`), these are expected:
- `svn revert ...` fails with `is not a working copy`
- `patch -p0 -i apatching_for_AFL_Persistent_fuzzing.diff` may fail because that diff was generated against another upstream revision.

Use the helper below instead.

## 1) Patch `server/main.c` in place

From repo root:

```bash
python3 Victims/fuzzingCVE/apply_persistent_harness.py \
  Victims/fuzzingCVE/httpd-2.4.17/server/main.c
```

This script creates a backup at:

```text
Victims/fuzzingCVE/httpd-2.4.17/server/main.c.orig
```

## 2) Build with AFL++

```bash
cd Victims/fuzzingCVE
CC=afl-clang-fast CXX=afl-clang-fast++ PREFIX="/usr/local/apache_afl_persistent/" ./compile_httpd_with_flags.sh
cd httpd-2.4.17
sudo env PATH="$PATH" make install
```

## 3) Required runtime knobs

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
echo core | sudo tee /proc/sys/kernel/core_pattern >/dev/null
```

## 4) Run AFL++

```bash
afl-fuzz \
  -i /path/to/Testcases \
  -o /path/to/Sessions/sess_persistent \
  -m none \
  -t 5000 \
  -- /usr/local/apache_afl_persistent/bin/httpd -X
```

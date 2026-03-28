# Fuzzing Apache httpd with AFL++ — Complete Setup Write-Up

## Overview

This document is a personal record of setting up coverage-guided fuzzing of Apache httpd using AFL++ with persistent mode. It covers every step taken, every error encountered and resolved, and explains what is happening under the hood at each stage. It is based on the 2017 blog post "Fuzzing Apache httpd server with American Fuzzy Lop + persistent mode" by Javi (n30m1nd), updated to work with modern tooling.

---

## Why Fuzz Apache This Way?

AFL (American Fuzzy Lop) is a coverage-guided fuzzer. It works by:

1. Instrumenting the target binary at compile time so every branch/edge in the code emits a signal to AFL.
2. Feeding mutated inputs to the program.
3. Tracking which inputs cause new code paths to be explored.
4. Retaining inputs that find new paths and discarding ones that don't.

The problem with fuzzing network servers like Apache is that AFL was designed for programs that read from a file or stdin — not from a socket. Apache listens on a TCP port, which means AFL can't directly pipe fuzz data into it.

The solution, originally devised by Robert Swiecky (Google) for honggfuzz, is elegant: **patch Apache so it spawns an internal thread that connects back to its own listening socket and sends the fuzz input**. This way everything — Apache's request processing AND the fuzz input delivery — happens within the same process, so AFL's instrumentation hooks capture all coverage data correctly.

The second key technique is **persistent mode**: instead of starting and killing Apache for every single fuzz input (slow), the patched Apache loops inside a `__AFL_LOOP()` construct, processing many inputs in one process lifetime. This dramatically increases throughput.

---

## Environment

- OS: Ubuntu 24.04 (running inside a QEMU VM)
- CPU: QEMU Virtual CPU version 2.5+ (important: no AVX/Skylake instructions)
- AFL version used: AFL++ 4.40c (built from source)
- Apache version: httpd 2.4.x (SVN trunk)
- Compiler: system clang (version 18, via `afl-clang-fast`)

---

## Folder Structure

```
~/projects/fuzzingExp/
├── Compilers/
│   ├── afl-2.52b/           # Original AFL (not used for final run)
│   ├── AFLplusplus/         # AFL++ (used)
│   └── clang+llvm-4.0.0-*/  # Old clang (caused problems, removed from PATH)
├── Victims/
│   └── apache24x/
│       ├── apr-1.7.6/
│       ├── aprutil-1.6.3/   # Renamed from apr-util-1.6.3 (glob fix)
│       ├── pcre-8.45/
│       ├── nghttp2-1.68.1/
│       ├── httpd-2.4.x/
│       └── compile_httpd_with_flags.sh
├── Testcases/
│   ├── GET_test
│   └── POST_test
└── Sessions/
    └── sess_persistent/
```

---

## Step 1 — Getting Dependencies

```bash
sudo apt install build-essential subversion pkg-config libssl-dev libexpat1-dev autoconf libtool-bin
```

Downloaded and unpacked:
- APR 1.7.6
- APR-util 1.6.3
- PCRE 8.45 (not PCRE2)
- nghttp2 1.68.1
- Apache httpd 2.4.x via SVN:

```bash
svn checkout http://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x httpd-2.4.x
```

Because httpd was checked out from SVN (not a release tarball), it had no `configure` script. It needed to be generated first:

```bash
cd httpd-2.4.x
./buildconf
```

---

## Step 2 — The APR Glob Ambiguity Fix

The compile script uses `cd apr-*` to enter the APR directory, but both `apr-1.7.6` and `apr-util-1.6.3` matched that glob, causing:

```
./compile_httpd_with_flags.sh: line 9: cd: too many arguments
```

**Fix:** rename apr-util so it no longer matches `apr-*`:

```bash
mv apr-util-1.6.3 aprutil-1.6.3
```

Then update line 13 of the compile script from `cd apr-util-*` to `cd aprutil-*`.

---

## Step 3 — The compile_httpd_with_flags.sh Script

The script compiles all dependencies and Apache itself, passing the chosen compiler through `CC`/`CXX` environment variables. Key points:

- Each dependency (`apr`, `aprutil`, `pcre`, `nghttp2`) is compiled first and its build path stored in a variable.
- Apache is then compiled with `-with-apr`, `--with-apr-util`, `--with-pcre`, `--with-nghttp2` pointing to those build paths.
- The `PREFIX` variable controls where everything is installed.

**Important change made:** removed `-march=skylake` from CFLAGS. This flag instructs the compiler to emit CPU instructions specific to Intel Skylake processors. Since the machine is a QEMU VM with a generic virtual CPU, Skylake instructions cause an `Illegal instruction` crash at runtime. Replaced with nothing (let the compiler default to a safe baseline).

```bash
# Before (broken in QEMU):
CFLAGS=" $CFLAGS -I$nghttp/lib/includes -march=skylake -g -ggdb -fno-builtin -fno-inline"

# After (works everywhere):
CFLAGS=" $CFLAGS -I$nghttp/lib/includes -g -ggdb -fno-builtin -fno-inline"
```

**sudo make install and PATH:** `sudo` strips the user PATH by default, so `sudo make install` couldn't find `clang`. Fixed by passing PATH explicitly:

```bash
sudo env PATH="$PATH" make install
```

---

## Step 4 — AFL++ Instead of AFL 2.52b

The blog post uses AFL 2.52b's `afl-clang-fast` (LLVM persistent mode compiler). This requires building the `llvm_mode` plugin inside AFL. However, AFL 2.52b's LLVM pass was written for LLVM 4.x and is incompatible with the system's modern LLVM/GCC headers (GCC 13 / C++20 ABI). Attempting to build it produced:

```
error: use of undeclared identifier '__builtin_fabsf128'
error: unknown type name 'FreezeInst'
```

**Solution:** use AFL++, which is the actively maintained successor to AFL and supports modern LLVM natively.

```bash
cd ~/projects/fuzzingExp/Compilers
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus

# IMPORTANT: make sure the old clang-4.0 is NOT in PATH
sudo rm /usr/local/bin/clang   # these were symlinked earlier
sudo rm /usr/local/bin/clang++
hash -r                         # clear shell command cache

CC=clang CXX=clang++ make
sudo make install
```

After this, `afl-clang-fast` and `afl-fuzz` are available system-wide.

---

## Step 5 — Patching Apache (The Core Technique)

### What the patch does

The patch modifies `server/main.c` to add the fuzzing harness. There are two patches in the blog post. The **second patch** (persistence mode) is the better one and was used. It was applied to a clean SVN checkout:

```bash
cd httpd-2.4.x
svn revert server/main.c
patch -p0 -i ../apatchistence_apache_for_AFL_fuzzing.diff
```

### How the technique works (under the hood)

#### 1. Network Namespace Isolation via `unshare()`

```c
void unsh(void) {
    unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS);
    mount("tmpfs", "/tmp", "tmpfs", 0, "");
    netIfaceUp("lo");
}
```

`unshare()` is a Linux syscall that detaches parts of the calling process's context from the rest of the system. Here it creates:

- A **new user namespace** (`CLONE_NEWUSER`): allows unprivileged namespace operations.
- A **new network namespace** (`CLONE_NEWNET`): gives this process its own loopback interface (`lo`), completely isolated from the host network. Multiple AFL workers can all bind to port 80 on their own private `lo` without conflicting.
- A **new mount namespace** (`CLONE_NEWNS`): allows mounting a fresh `tmpfs` on `/tmp` so each worker has its own scratch space for logs/PID files.

`netIfaceUp("lo")` then brings the loopback interface up inside the new namespace so Apache can actually listen on it.

This is the critical insight that makes running many parallel AFL workers possible — each gets its own isolated network and filesystem.

#### 2. The Fuzzing Loop Thread

```c
static void *GETDATA(void *arg) {
    int BUFSIZE = 1024 * 1024;
    char buf[BUFSIZE + 1];
    while (__AFL_LOOP(10000)) {
        memset(buf, 0, BUFSIZE);
        size_t read_bytes = read(0, buf, BUFSIZE);  // Read fuzz input from stdin
        // ... connect to Apache's own socket and send buf ...
    }
    _exit(0);
}
```

`__AFL_LOOP(N)` is an AFL++ macro that implements persistent mode. Instead of forking a new process for every fuzz input, the process loops up to N times before exiting. AFL's fork server handles the reset between iterations. This is what makes persistent mode so much faster than the basic mode.

The thread reads AFL's fuzz input from **stdin** (AFL feeds it via a pipe), then opens a TCP connection to `127.0.0.1:80` (Apache's listener on the private loopback) and sends the data. Apache processes it as a real HTTP request, and AFL observes the coverage bitmap to decide whether to keep this input.

#### 3. Main thread continues normally

The `LAUNCHTHR()` call fires the fuzzing thread as a detached pthread, then `main()` continues into Apache's normal initialization sequence — loading config, binding the port, starting the MPM. The fuzzing thread waits briefly (`usleep(10000)`) to give Apache time to get ready before sending the first request.

### Fixes required in the patch for modern compilers

The original patch had two issues that caused compilation failures under modern clang:

**1. Missing `#include <sys/mount.h>`** — the `mount()` call in `unsh()` requires this header. Modern clang enforces ISO C99 "no implicit function declarations" strictly.

**2. Wrong `GETDATA` signature** — `pthread_create` requires the thread function to be `void *(*)(void *)`. The patch had it as `void (process_rec *)`, causing:
```
error: incompatible function pointer types
```

Fixed to:
```c
static void *GETDATA(void *arg) { ... }
```
and:
```c
pthread_create(&t, &attr, GETDATA, NULL);
```

---

## Step 6 — Compiling Apache with AFL++ Instrumentation

```bash
cd ~/projects/fuzzingExp/Victims/apache24x/
CC=afl-clang-fast CXX=afl-clang-fast++ PREFIX="/usr/local/apache_afl_persistent/" ./compile_httpd_with_flags.sh
cd httpd-2.4.x
sudo env PATH="$PATH" make install
```

`afl-clang-fast` is a compiler wrapper that inserts AFL++'s PCGUARD instrumentation at every branch point in the code. During fuzzing, each time a branch is taken, a shared memory bitmap is updated. AFL++ reads this bitmap after each execution to determine coverage.

You can see the instrumentation working in the build output:
```
[+] Instrumented 394 locations with no collisions (non-hardened mode)
```

---

## Step 7 — Enabling Unprivileged Namespaces

The `unshare(CLONE_NEWUSER | ...)` call requires either root or the kernel setting `unprivileged_userns_clone=1`:

```bash
sudo su
sysctl -w kernel.unprivileged_userns_clone=1
```

Without this, the `mount()` call fails with `Permission denied` even as root in some kernel configurations.

---

## Step 8 — Creating Testcases

AFL needs at least one valid seed input to start with:

```bash
mkdir -p ~/projects/fuzzingExp/Testcases
echo -e "GET / HTTP/1.0\r\n\r\n" > ~/projects/fuzzingExp/Testcases/GET_test
echo -e "POST / HTTP/1.0\r\nContent-Length: 0\r\n\r\n" > ~/projects/fuzzingExp/Testcases/POST_test
```

These are minimal valid HTTP requests. AFL will mutate them — flipping bytes, inserting tokens, splicing inputs — to explore Apache's parsing code.

---

## Step 9 — Running the Fuzzer

```bash
sudo su
echo core > /proc/sys/kernel/core_pattern      # Required: AFL needs crash signals, not core dumps to pipe
sysctl -w kernel.unprivileged_userns_clone=1

afl-fuzz \
  -i ~/projects/fuzzingExp/Testcases \
  -o ~/projects/fuzzingExp/Sessions/sess_persistent \
  -m none \
  -t 5000 \
  -- /usr/local/apache_afl_persistent/bin/httpd -X
```

Flag explanations:
- `-i`: input directory (seed testcases)
- `-o`: output directory (session state, crashes, queue)
- `-m none`: no memory limit (Apache is large)
- `-t 5000`: 5 second timeout per execution (Apache needs time to boot)
- `-X`: Apache single-worker debug mode (no forking)

AFL++ detects `__AFL_LOOP` in the binary and activates persistent mode automatically, shown by:
```
[+] Persistent mode binary detected.
```

---

## Problems Encountered and Solutions

| Problem | Cause | Fix |
|---|---|---|
| `cd: too many arguments` | `apr-*` glob matched both APR and APR-util | Renamed `apr-util-1.6.3` to `aprutil-1.6.3` |
| `expat.h not found` | Missing libexpat dev package | `sudo apt install libexpat1-dev` |
| `clang: command not found` during sudo install | sudo strips user PATH | `sudo env PATH="$PATH" make install` |
| `./configure: No such file or directory` | SVN checkout has no configure script | Run `./buildconf` inside httpd-2.4.x |
| `afl-llvm-pass.so: undefined symbol` | Old AFL 2.52b incompatible with GCC 13 ABI | Switched to AFL++ |
| `Illegal instruction` at runtime | `-march=skylake` on QEMU virtual CPU | Removed `-march=skylake` from CFLAGS |
| `tmpfs: Permission denied` | Kernel blocking unprivileged namespaces | `sysctl -w kernel.unprivileged_userns_clone=1` as root |
| Hunk #4 FAILED during patch | Change was already present in the source | Safe to ignore; result is correct |
| `mount()` compile error | Missing `#include <sys/mount.h>` | Added include to patched main.c |
| `pthread_create` type error | GETDATA had wrong signature | Changed to `void *GETDATA(void *arg)` |
| `Program not found` in afl-fuzz | `make install` hadn't run for httpd | `cd httpd-2.4.x && sudo env PATH="$PATH" make install` |

---

## What AFL++ Is Doing Under the Hood

```
┌─────────────────────────────────────────────────────────┐
│                        AFL++ Process                    │
│                                                         │
│  1. Fork server handshake with httpd at startup         │
│  2. Take a seed from the queue                          │
│  3. Mutate it (bit flips, byte substitutions, splicing) │
│  4. Write mutated input to pipe → httpd reads via       │
│     read(0, buf, BUFSIZE) in GETDATA thread             │
│  5. httpd's GETDATA thread connects to 127.0.0.1:80     │
│     and sends the mutated HTTP bytes                    │
│  6. Apache parses the request, executes handlers        │
│  7. Coverage bitmap updated at every instrumented branch│
│  8. AFL++ reads bitmap: new path found? → save to queue │
│  9. Crash? → save to crashes/                           │
│  10. __AFL_LOOP loops back to step 4 (up to 10000x)     │
└─────────────────────────────────────────────────────────┘
```

The key insight is that all of this — AFL++, httpd, and the internal connection — happens within a **single process** (after the initial fork). This is why AFL's shared memory bitmap captures all coverage correctly. A separate process connecting over the network would not be instrumented.

---

## Notes for Future Reference

- To fuzz with multiple parallel workers, run multiple `afl-fuzz` instances with `-M main` and `-S worker1`, `-S worker2` etc., each with its own output directory. Each gets its own namespace via `unshare()`.
- The stability metric in AFL++ may be low (below 50%) due to Apache's multithreading — this is expected and mentioned in the original blog post.
- Crashes found in `sess_persistent/default/crashes/` can be replayed with: `cat crash_file | /usr/local/apache_afl_persistent/bin/httpd -X`
- To fuzz different Apache modules, enable them in the httpd.conf and recompile. Different modules = different code paths = different attack surface.
- AFL++ supersedes AFL 2.52b in every meaningful way: better instrumentation, better mutation strategies, active maintenance, and works with modern compilers.
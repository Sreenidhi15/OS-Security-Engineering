# Command Injection Demo — CWE-78

A side-by-side demonstration of a vulnerable shell implementation and its hardened equivalent, showing how the choice of `system()` vs `execvp()` determines whether a shell is exploitable via OS command injection.

---

## The Vulnerability

**CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)**

When a program uses `system()` to execute user-supplied input, it passes that input to `/bin/sh -c` as a raw string. The shell interpreter processes the string before execution, which means shell metacharacters are active:

| Metacharacter | Effect |
|--------------|--------|
| `;` | Run second command unconditionally |
| `&&` | Run second command if first succeeds |
| `\|` | Pipe output of first command to second |
| `\|\|` | Run second command if first fails |
| `$()` | Execute subshell and substitute output |
| `` ` `` | Execute subshell (legacy syntax) |

**Attack example:**

The programmer intends the user to type: `ls`  
The attacker types: `ls ; cat /etc/shadow`

With `system()`, the shell sees two commands separated by `;` and executes both. With `execvp()`, the `;` is passed as a literal filename argument to `ls` — the injection is inert.

---

## Files

| File | Description |
|------|-------------|
| `vuln_shell.c` | Vulnerable shell using `system()` — comments explain exactly where and why the vulnerability exists |
| `safe_shell.c` | Hardened shell using `fork()` + `execvp()` — comments explain why metacharacters are inert |
| `exploit_demo.py` | Python script that sends four injection payloads to both shells and compares output |

---

## How to Run

```bash
# Compile both shells
gcc -o vuln_shell vuln_shell.c
gcc -o safe_shell safe_shell.c

# Run the automated exploit demo
python3 exploit_demo.py

# Or test manually
./vuln_shell
vuln$ ls ; whoami          # injected — runs ls THEN whoami
vuln$ echo hello && id     # injected — runs echo THEN id

./safe_shell
safe$ ls ; whoami          # inert — semicolon passed as filename arg to ls
safe$ echo hello && id     # inert — && passed as literal string to echo
```

---

## Expected Output Comparison

**vuln_shell** — injection succeeds:
```
vuln$ ls ; whoami
audit_logger.c  audit_logger.h  myshell.c  README.md
sreenidhi          <-- injected whoami output
```

**safe_shell** — injection blocked:
```
safe$ ls ; whoami
ls: cannot access ';': No such file or directory
ls: cannot access 'whoami': No such file or directory
```

The safe shell treats `;` and `whoami` as filenames to list — not commands to execute.

---

## NIST SP 800-53 Control Mapping

| Control | Name | Application |
|---------|------|-------------|
| SI-10 | Information Input Validation | `vuln_shell.c` fails this control — no validation before passing input to `system()`. `safe_shell.c` satisfies it — input is tokenized into discrete argument strings with no shell interpolation. |
| SI-3 | Malicious Code Protection | Command injection is a code execution vector; `execvp()` eliminates the shell interpreter attack surface. |
| AC-3 | Access Enforcement | In a setuid context, command injection via `system()` allows privilege escalation — the injected command runs with elevated privileges. `execvp()` does not introduce this exposure. |

---

## Why This Matters for Security Engineering

This vulnerability pattern appears in:

- Web application backends that call `os.system()` or `shell=True` in Python subprocess calls
- PHP applications using `exec()` or `shell_exec()` with user input
- C/C++ programs using `system()` in embedded firmware (direct relevance to CactiLab firmware work)
- Any program that constructs a command string from untrusted input and passes it to a shell

The fix is always the same: bypass the shell interpreter entirely by passing an argument array directly to the OS via `execve()`/`execvp()` or equivalent.


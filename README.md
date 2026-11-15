# mysql323-audit

Check MySQL323 (`OLD_PASSWORD()`) password hashes against a wordlist, offline.

```sh
python3 mysql323_audit.py --hashes users.csv --wordlist rockyou.txt
```

CSV is `login,hash` by default (change with `--id-col` / `--hash-col` / `--delimiter`).
Output is `login<tab>password<tab>hash`.

Flags: `--mutations`, `--show-dupes`, `--output FILE`, `--self-test`.

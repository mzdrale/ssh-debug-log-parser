# ssh-debug-log-parser

IMPORTANT: Work in progress! Still not working as desired!

While I was working on some project, I had to find what SSH clients, ciphers, auth methods and algorithms users are using. I wrote this tool to parse SSH server logs, with debug enabled.

# Build

```bash
❯ make
```

# Usage

```bash
❯ ssh-debug-log-parser --help
Usage:
  -f, --log-files string       Log files to parse, comma separated list
  -o, --output-format string   Output format (list, table, json-file) (default "list")
  -a, --print-all              Print all info
      --print-client-ciphers   Print KexClientServerCiphers
      --print-failed-logins    Print failed login IP addresses
      --print-remote-ips       Print remote IP addresses
      --print-server-ciphers   Print KexServerClientCiphers
  -V, --version                Print version
❯
```

# Demo

![Demo](images/demo.gif)
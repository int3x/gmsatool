# gmsatool

A gMSA tool for enumeration, access management, and password retrieval.

![logo](logo.png)

## Installation

```console
$ uv tool install https://github.com/int3x/gmsatool.git
```

## Usage

```console
$ gmsatool enum -h
                                                                                
 Usage: gmsatool enum [OPTIONS] COMMAND [ARGS]...                               
                                                                                
 Subcommands for enumeration                                                    
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ find-gmsa   Find gMSA accounts, users with password read access, and users   │
│             who can modify that access                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

```console
$ gmsatool gmsa -h
                                                                                
 Usage: gmsatool gmsa [OPTIONS] COMMAND [ARGS]...                               
                                                                                
 Subcommands for reading gMSA password and access manipulation                  
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ read-password   Read gMSA password of a target account                       │
│ access          Grant or deny gMSA password read privilege to a principal    │
│ auto            Automated enumeration and abuse of gMSA privileges           │
│                 (experimental)                                               │
╰──────────────────────────────────────────────────────────────────────────────╯
```

```console
$ gmsatool enum find-gmsa -h
                                                                                
 Usage: gmsatool enum find-gmsa [OPTIONS]                                       
                                                                                
 Find gMSA accounts, users with password read access, and users who can modify  
 that access                                                                    
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ *  --domain    -d      TEXT  The domain FQDN [required]                      │
│    --target            TEXT  The target gMSA account (opional)               │
│    --dc                TEXT  The target domain controller (IP or FQDN). If   │
│                              omitted, defaults to the domain FQDN            │
│    --username  -u      TEXT  The username                                    │
│    --password  -p      TEXT  The password                                    │
│    --hash      -H      TEXT  The NT hash for the domain account              │
│                -k            Use Kerberos authentication. Default TGT        │
│                              location is /tmp/krb5cc_`id -u`                 │
│    --ldaps                   Use LDAPS (port 636)                            │
│    --verbose   -v            Enable verbose output                           │
│    --help      -h            Show this message and exit.                     │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Acknowledgements

Kudos to @ThePirateWhoSmellsOfSunflowers, @skelsec and [impacket](https://github.com/fortra/impacket) contributors.

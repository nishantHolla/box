# box

A CLI tool for filesystem encryption using OpenSSL's AES in C

# Usage (linux and macOS)

- Clone the repository

```bash
git clone https://github.com/nishantHolla/box
cd box
```

- Compile binary and place it in PATH. (restart terminal after running the command)

```bash
make
sudo mv ./out/box /bin
```

- Create a box in the root of the directory that you want to encrypt.

```bash
box create <path_to_directory>
```

- Wrap the box (encrypt)

```bash
box wrap <path_to_directory>
```

- Unwrap the box (decrypt)

```bash
box unwrap <path_to_directory>
```

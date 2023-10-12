# box

A simple CLI software for filesystem encryption.

# Usage (for linux)

- Clone this repo
```
git clone https://github.com/nishantHolla/box.git
```

- Go to the repo
```
cd ./box
```

- Make the binary
```
make release
```

- Move the binary to the path
```
mv ./output/box $HOME/.local/bin
```

- Go to the directory which you want to encrypt

- Create a box in the current directory and give it a password
```
box create .
```

- Encrypt the content of the directory
```
box wrap .
```

- Decrypt the content of the directory
```
box unwrap .
```

# B593s-22_SSH
Get ssh login for HUAWEI B593s-22 LTE modem/router

[![Donate](https://dl.ugjka.net/Donate-PayPal-green.svg)](https://www.paypal.me/ugjka)

## Hardware and Firmware version you need
```Product Information
Model:
B593s-22
SN:
S2Z7S15624000308
Hardware version:
Ver.B
Firmware version:
V200R001B270D10SP00C00
Firmware build time:
Aug 20 2014 / 11:22:16
```

## Usage
```
Usage of ./B593s-22_SSH:
  -host string
      B593s-22's ip adress (default "192.168.1.1")
  -pass string
      web gui admin password
```

## Output

```
[ugjka@archee B593s-22_SSH]$ ./B593s-22_SSH -pass admin
Credentials found! Use:
*************************
sshpass -p '02D8B197' ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc admin@192.168.1.1
*************************
Once in, type "shell" and hit enter! :)
```

# Binaries

https://github.com/ugjka/B593s-22_SSH/releases

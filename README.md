This project demonstrates the sha256 length-extension attack when used to hash secrets.

Usage:

```shell
# The server generates the MAC for the legitimate message
$ hash=$(echo -n user=magodo | go run -C ./server ./ --secret 123 mac)

# The attacker guess the secret length (i.e. 3) and forge the message and (valid) hash
$ forged_msg=$(go run -C ./attack ./ --msg user=magodo --hash $hash --secret-len 3 --append "&role=admin" --show-msg)
$ forged_hash=$(go run -C ./attack ./ --msg user=magodo --hash $hash --secret-len 3 --append "&role=admin" --show-hash)

# The server verifies the forged message against the forged hash
$ echo -n $forged_msg | go run -C ./server ./ --secret 123 verify --hash $forged_hash
$ echo $?
0
```

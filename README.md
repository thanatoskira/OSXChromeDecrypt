# OSXChromeDecrypt
Decrypt Google Chrome and Chromium Passwords and Credit Cards on macOS / OS X. Works on all versions of Python 2.x - a default install on macOS / OS X, so no dependencies are needed.

These are the passwords and CC's saved via the "Would you like to remember this password" popup when you login to a website.

Great for if you want to export all of your passwords and CC's with one fell swoop (it is very quick), as oppposed to manually selecting each one through Chrome's UI.

Also great for forensic analysis, as you can obtain the safe storage key through a variety of methods.

# Information

1. Look for any encrypted password data stored in ```~/Library/Application Support/Google/Chrome/*/Login Data``` 
2. Get the decryption key from the keychain WITHOUT having to confirm the users password!
3. Use this key to decrypt the passwords.
4. Print out all of the passwords in a neat format.
  
# Example usage: 

```python ChromePasswords.py``` 

Then confirm keychain access by clicking "allow"

```
OUTPUT:

[1] https://xxxxxxxx.yyyyyyy.zzzzzzz/login.php
	User: bobloblaw
	Pass: supersecretpassword
  
[2] https://timcook.apple.com/apple-login
	User: tim
	Pass: cook1010101

[3] VISA: 
	Card Name: Bob Lob Law
	Card Number: 4567891011121314
	Expiration Date: 10/2017
```

**Note**: Big thanks to @mitsuhiko (https://github.com/mitsuhiko/python-pbkdf2) for a native python pbkdf2_hmac implementation for OSX < 10.11!
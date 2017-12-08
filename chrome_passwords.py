# -*- coding: utf-8 -*-
import sqlite3
import binascii
import subprocess
import base64
import operator
import tempfile
import sys
import shutil
import glob
import hmac
import struct
import itertools


def pbkdf2_bin(password, salt, iterations, keylen=16):
    # thanks to @mitsuhiko for this function
    # https://github.com/mitsuhiko/python-pbkdf2
    _pack_int = struct.Struct('>I').pack
    hashfunc = sha1
    mac = hmac.new(password, None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())

    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = itertools.starmap(operator.xor, itertools.izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]


try:
    from hashlib import pbkdf2_hmac
except ImportError:
    # python version not available (Python <2.7.8, macOS < 10.11)
    # use @mitsuhiko's pbkdf2 method
    pbkdf2_hmac = pbkdf2_bin
    from hashlib import sha1


def chrome_decrypt(encrypted, safe_storage_key):
    """
    AES decryption using the PBKDF2 key and 16x ' ' IV
    via openSSL (installed on OSX natively)

    salt, iterations, iv, size @
    https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
    """

    iv = ''.join(('20', ) * 16)
    key = pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]

    hex_key = binascii.hexlify(key)
    hex_enc_password = base64.b64encode(encrypted[3:])

    # send any error messages to /dev/null to prevent screen bloating up
    # (any decryption errors will give a non-zero exit, causing exception)
    try:
        decrypted = subprocess.check_output(
            "openssl enc -base64 -d "
            "-aes-128-cbc -iv '{}' -K {} <<< "
            "{} 2>/dev/null".format(iv, hex_key, hex_enc_password),
            shell=True)
    except subprocess.CalledProcessError:
        decrypted = "Error decrypting this data"

    return decrypted


def chrome_db(chrome_data, content_type):
    """
    Queries the chrome database (either Web Data or Login Data)
    and returns a list of dictionaries, with the keys specified
    in the list assigned to keys.

    @type chrome_data: list
    @param chrome_data: POSIX path to chrome database with login / cc data
    @type content_type: string
    @param content_type: specify what kind of database it is (login or cc)

    @rtype: list
    @return: list of dictionaries with keys specified in the keys variable
             and the values retrieved from the DB.
    """
    # work around for locking DB
    copy_path = tempfile.mkdtemp()
    with open(chrome_data, 'r') as content:
        dbcopy = content.read()
    with open("{}/chrome".format(copy_path), 'w') as content:
        # if chrome is open, the DB will be locked
        # so get around this by making a temp copy
        content.write(dbcopy)

    database = sqlite3.connect("{}/chrome".format(copy_path))

    if content_type == "Web Data":
        sql = ("select name_on_card, card_number_encrypted, expiration_month, "
               "expiration_year from credit_cards")
        keys = ["name", "card", "exp_m", "exp_y"]

    else:
        sql = "select username_value, password_value, origin_url from logins"
        keys = ["user", "pass", "url"]

    db_data = []
    with database:
        for values in database.execute(sql):
            if not values[0] or (values[1][:3] != b'v10'):
                continue
            else:
                db_data.append(dict(zip(keys, values)))
    shutil.rmtree(copy_path)

    return db_data


def utfout(inputvar):
    """
    Cleans a variable for UTF8 encoding on some enviroments
    where python will break with an error
    @credit: koconder

    @type inputvar: string
    @param inputvar: string to be cleaned for UTF8 encoding
    @rtype inputvar: terminal compatible UTF-8 string encoded
    @return inputvar: terminal compatible UTF-8 string encoded
    """
    return inputvar.encode(sys.stdout.encoding, errors='replace')


def chrome(chrome_data, safe_storage_key):
    """
    Calls the database querying and decryption functions
    and displays the output in a neat and ordered fashion
    (with colors)

    @type chrome_data: list
    @param chrome_data: POSIX path to chrome database with login / cc data
    @type safe_storage_key: string
    @param safe_storage_key: key from keychain that will be used to
                             derive AES key.

    @rtype: None
    @return: None. All data is printed in this function, which is it's primary
             function.
    """
    for profile in chrome_data:
        # web data -> credit cards
        # login data -> login data

        green = "\033[32m"
        violet = "\033[35m"
        blue = "\033[34m"
        bold = "\033[1m"
        end = "\033[0m"

        if "Web Data" in profile:
            db_data = chrome_db(profile, "Web Data")

            print("{}Credit Cards for Chrome "
                  "Profile{} -> [{}{}{}]".format(blue, end, violet,
                                                 profile.split("/")[-2], end))

            for i, entry in enumerate(db_data):
                entry["card"] = chrome_decrypt(entry["card"], safe_storage_key)
                cc_dict = {
                    '3': 'AMEX',
                    '4': 'Visa',
                    '5': 'Mastercard',
                    '6': 'Discover'
                }

                brand = "Unknown Card Issuer"
                if entry["card"][0] in cc_dict:
                    brand = cc_dict[entry["card"][0]]

                print("  {}[{}]{} {}{}{}".format(green, i + 1, end, bold,
                                                 brand, end))
                print("\t{}Card Holder{}: {}".format(green, end,
                                                     utfout(entry["name"])))
                print("\t{}Card Number{}: {}".format(green, end,
                                                     utfout(entry["card"])))
                print("\t{}Expiration{}: {}/{}".format(green, end,
                                                       utfout(entry["exp_m"]),
                                                       utfout(entry["exp_y"])))

        else:
            db_data = chrome_db(profile, "Login Data")

            print("{}Passwords for Chrome "
                  "Profile{} -> [{}{}{}]".format(blue, end, violet,
                                                 profile.split("/")[-2], end))

            for i, entry in enumerate(db_data):
                entry["pass"] = chrome_decrypt(entry["pass"], safe_storage_key)

                print("  {}[{}]{} {}{}{}".format(green, i + 1, end, bold,
                                                 utfout(entry["url"]), end))
                print("\t{}User{}: {}".format(green, end, utfout(
                    entry["user"])))
                print("\t{}Pass{}: {}".format(green, end, utfout(
                    entry["pass"])))


if __name__ == '__main__':
    root_path = "/Users/*/Library/Application Support/Google/Chrome"
    login_data_path = "{}/*/Login Data".format(root_path)
    cc_data_path = "{}/*/Web Data".format(root_path)
    chrome_data = glob.glob(login_data_path) + glob.glob(cc_data_path)
    safe_storage_key = subprocess.Popen(
        "security find-generic-password -wa "
        "'Chrome'",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True)
    stdout, stderr = safe_storage_key.communicate()

    if stderr:
        print("Error: {}. Chrome entry not found in keychain?".format(stderr))
        sys.exit()
    if not stdout:
        print("User clicked deny.")

    safe_storage_key = stdout.replace("\n", "")
    chrome(chrome_data, safe_storage_key)

import hashlib
import sys

import requests


def requestApi_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # print(res)

    if res.status_code != 200:
        raise RuntimeError(f"Runtime error!{res.status_code}, check the api")
    return res


def getPass_leaks(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # print(h, count)
        if h == hash_to_check:
            return count
    return 0


def checkPwned_api(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = requestApi_data(first5_char)
    # print(response)
    return getPass_leaks(response, tail)


def main(args):
    for password in args:
        count = checkPwned_api(password)
        if count:
            print(f"{password} was found {count} times. You have to change your password!")
        else:
            print(f"{password} was NOT found. You are safe.")
    return 'done!'


pass_list = []
with open('word_list.txt', 'r') as file:
    try:
        for password in file.readlines():
            pass_list.append(password.strip('\n'))
    except FileNotFoundError as err:
        print(f'File not found, error {err} ')

    main(pass_list)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

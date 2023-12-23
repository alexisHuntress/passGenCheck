import requests
import hashlib
import sys
import os
# Use an API to check for password leaks
#
# Increase security by reading from a named file
#
# Add a password generator that then checks for security and stores the password along with a user id
# encripted in a sepperate .txt file to act as a password vault.
#
# Add a GUI for desktop and mobile.
#

# Delete task when complete


def api_data_request(query_char): # API request
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error: {res.status_code}, check API')
    return res


def get_pass_leak_count(hashes, hash_to_check): # Loop through result
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password): # Hash and encode input
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_char, tail = sha1password[:5], sha1password[5:]
    response = api_data_request(first_five_char)
    return get_pass_leak_count(response, tail)


def main(args): # Main functionality
    count = pwned_api_check(password)
    if count:
        print(f'{password} was found {count} times. Change immediately')
    else:
        print(f'{password} secure')
    return 'Finished'

main(sys.argv[1:])

if __name__ ==  '__main__':
    sys.exit(main(sys.argv[1:]))
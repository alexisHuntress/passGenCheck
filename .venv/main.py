import requests
import hashlib
import secrets
import string
import sys
import os


# Store the password along with an user id encripted in a sepperate .txt file to act as a password vault.
# Add a GUI for desktop and mobile.
#

# Delete task when complete
def pass_generator(): # Generates a secure password
    try:
        or_length = sys.argv[1]
        if  len(sys.argv) > 1:
            chars = '~`!@#$%^&*_-+=<,>.?'
            alphabet = string.ascii_letters + string.digits + chars
            while True:
                password = ''.join(secrets.choice(alphabet) for i in range(int(or_length)))
                if (any(c.islower() for c in password)
                        and any(c.isupper() for c in password)
                        and sum(c.isdigit() for c in password) >= 3):
                    break
            return password
    except:
        length = int(input('Password Length: '))
        alphabet = string.ascii_letters + string.digits
        while True:
            password = ''.join(secrets.choice(alphabet) for i in range(int(length)))
            if (any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and sum(c.isdigit() for c in password) >= 3):
                break
        return password



def security_check():
    password = pass_generator()
    count = pwned_api_check(password)
    if count:
        print(f'{password} was found {count} times. Change immediately')
    else:
        print(f'{password} secure')


def file_read(args): # Read data from txt file for security
    try:
        with open(f'C:/Users/hunte/Desktop/{args}.txt', mode='r', encoding='utf-8') as f:
            f = f.readlines()
    except FileNotFoundError as e:
        print("File not Found")
    p = [p.strip() for p in f]
    return p

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
    for password in file_read(sys.argv[1]):
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. Change immediately')
        else:
            print(f'{password} secure')
    return 'Finished'

security_check()
# if __name__ ==  '__main__':
#     sys.exit(main(sys.argv[1]))
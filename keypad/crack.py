import requests

URL = 'https://keypad.elfu.org/checkpass.php?i={}&resourceId=b91ae494-04d0-4dc5-b8e1-6d83758ba2e2'

primes = open('primes').read().split()

keys = ['1', '3', '7']
for prime in primes:
    valid = True
    dupes = {}
    for digit in prime:
        if digit not in keys:
            valid = False
            break
        dupes[digit] = dupes.get(digit, 0) + 1
    if not valid:
        continue
    if int(prime) < 1000 or int(prime) > 10000:
        continue
    if not 2 in dupes.values():
        continue
    # Make the request
    print('trying {}'.format(prime))
    response = requests.get(URL.format(prime))
    if not response.ok:
        print('bad {}'.format(prime))
        continue
    success = response.json()['success']
    if not success:
        continue
    print('Got it! {}'.format(prime))
    break
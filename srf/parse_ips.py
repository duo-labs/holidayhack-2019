import json

with open('initial_ips.txt') as blocklist:
    ips = []
    for ip in blocklist.readlines():
        ip = ip.strip('"\n')
        if not ip or ip in ips or ip.startswith('10.') or ip.startswith('#'):
            continue
        ips.append(ip)
    # print(', '.join(sorted(ips)))
    # print('Loaded {} IP addresses'.format(len(ips)))

# Load all the affected user agents
uas = {}
with open('http.json', 'r') as logs:
    for log in logs.readlines():
        parsed = json.loads(log)
        ip = parsed['id.orig_h']
        ua = parsed['user_agent']
        if ip not in ips:
            continue
        if ua not in uas:
            uas[ua] = []

# Now, we can go back and gather all the IP addresses that have the identified
# user agents
with open('http.json', 'r') as logs:
    for log in logs.readlines():
        parsed = json.loads(log)
        ip = parsed['id.orig_h']
        ua = parsed['user_agent']
        if ua not in uas:
            continue
        # Only add unique IP addresses
        if ip not in uas[ua]:
            uas[ua].append(ip)
        # Let's also keep track of the total IPs
        if ip not in ips:
            ips.append(ip)

for ua, uaips in uas.items():
    print('{}\t{}'.format(len(uaips), ua))

# Double-check the "maybes"
maybe_uas = [
    'Mozilla/5.0 (X11; U; Linux i686; it; rv:1.9.0.5) Gecko/2008121711 Ubuntu/9.04 (jaunty) Firefox/3.0.5',
    'Mozilla/5.0 (Windows; U; Windows NT 5.2; sk; rv:1.8.1.15) Gecko/20080623 Firefox/2.0.0.15',
    'Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_4_11; fr) AppleWebKit/525.18 (KHTML, like Gecko) Version/3.1.2 Safari/525.22',
    'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.8) Gecko/20071004 Firefox/2.0.0.8 (Debian-2.0.0.8-1)'
]

with open('http.json', 'r') as logs:
    for log in logs.readlines():
        parsed = json.loads(log)
        uri = parsed['uri']
        ip = parsed['id.orig_h']
        ua = parsed['user_agent']
        if ua not in maybe_uas:
            continue
        if '<script>' not in uri and \
            '<script>' not in parsed['host'] and \
            '/etc/passwd' not in uri and \
            'UNION' not in uri and \
            'UNION' not in ua and \
            '1=1' not in parsed['username']:
                print('Removing {}\t{}\t{}'.format(ip, uri, ua))
                ips.remove(ip)

with open('ips.txt', 'w') as ip_file:
    for ip in sorted(ips):
        ip_file.write(ip + '\n')

print(', '.join(sorted(ips)))
print('IP addresses to block: {}'.format(len(ips)))
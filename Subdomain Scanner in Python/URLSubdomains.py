import requests

domain = input("Enter domain name: ")

file = open('subdomains_name.txt', 'r')
content = file.read()

subdomainsNames = content.splitlines()

print('-----------Scanner Started-----------')
print('----URL after scanning subdomains----')
print('\n')

for subdomain  in  subdomainsNames:
    url1 = f"http://{subdomain}.{domain}"
    url2 = f"https://{subdomain}.{domain}"

    try:
        requests.get(url1)
        print(f'[+] {url1}')
        requests.get(url2)
        print(f'[+] {url2}')
    except requests.ConnectionError:
        pass

print('\n')
print('----Scanning Finished----')
print('-----Scanner Stopped-----')

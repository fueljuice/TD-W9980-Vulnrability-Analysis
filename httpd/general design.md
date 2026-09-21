## the general design

the httpd binary is a webserver daemon process that runs the GUI of the router and lets a user configure the settings of firewalls, dns, port forwarding etc, and perform software updates. it also have a auth system that demands login credentials. here i will review the entire workflow of this webserver by reversing it using IDA  <br> <br><br><br>

`void __noreturn http_init_main()` starts with some setup functions and then does this
```c
  sub_405690(2, "/cgi/conf.bin", 0, &sub_406960, off_41E530);
  sub_405690(2, "/cgi/confup", 0, sub_406728, off_41E530);
  sub_405690(2, "/cgi/bnr", 0, &sub_406610, off_41E530);
  sub_405690(2, "/cgi/softup", 0, sub_4063F0, off_41E530);
  sub_405690(2, "/cgi/softburn", 0, &sub_4062E0, off_41E530);
  sub_405690(2, "/cgi/log", 0, &sub_406A70, off_41E530);
  sub_405690(2, "/cgi/info", 0, sub_4084E4, off_41E530);
  sub_405690(2, "/cgi/lanMac", 0, &sub_4082DC, off_41E530);
  sub_405690(2, "/cgi/auth", 0, &sub_407EB0, off_41E530);
  sub_405690(2, "/cgi/pvc", 0, sub_4081E0, off_41E530);
  sub_405690(2, "/cgi/wlanButton", 0, sub_408160, off_41E530);
  sub_405690(2, "/cgi/ansi", 0, sub_408660, off_41E530);
  sub_405820();
  if ( sub_403000() )
    exit(-1);
  signal(13, (__sighandler_t)1);
  dm_shmInit(0);
  sub_401CA0();
  sub_4025E4();
```

it essentialy makes a linked list in `off_41E530` of every endpoint and its metadata. right after that it calls `sub_4025E4();` which is the main function to handle the requests themselves:
```c
void __noreturn sub_4025E4()
{ /* i removed the variable declrations */
  v42 = 2;
LABEL_3:
  v0 = 4;
  while ( 1 )
  {
LABEL_4:
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    memcpy(&dest, dword_432E9C, sizeof(dest));
    v1 = select(dword_41EA20 + 1, &dest, nullptr, nullptr, &timeout);
    if ( v1 == -1 )
    {
      v2 = *_errno_location();
      if ( v2 == 4 )
        continue;
      if ( v2 != 9 )
      {
        fprintf(stderr, "#file: %s;line: %d; error = ", "src/http_inetd.c", 875);
        perror("");
        fputs("#error && exit: select error return, may be no memory\n", stderr);
        exit(-1);
      }
    }
    else if ( !v1 )
    {
      v42 = 2;
      goto LABEL_3;
    }
    v3 = v0;
    if ( ((dest.__fds_bits[(unsigned int)dword_433850 >> 5] >> dword_433850) & 1) == 0 )
      break;
    sub_401DE8();
  }
/* continues on to handle error exceptions */
```
this is the webserver's main loop that works on the select() api the synchrounsly waits for an fd. it later calls `sub_401DE8()` which create a new `socket()` a bind() and a listen() to the fd it found from select and calls `sub_40402C`. <br> 
`sub_40402C` is the http request header parser. generally it performs these checks:

post or get
```c
  if ( memcmp(v61, "GET", v4 - v61) )
  {
    v7 = memcmp(v61, "POST", v6);
    v3 = 405;
    if ( v7 )
      goto LABEL_135;
    s[1] = 2;
  }
```

http version
```c
  v11 = memcmp(v15, "HTTP/1.1", v16) == 0;
  v17 = 2;
  if ( !v11 )
  {
    v18 = memcmp(v15, "HTTP/1.0", v16);
    v3 = 505;
    if ( !v18 )
    {
      v17 = 1;
      goto LABEL_23;
    }
```
boundary and multipart
```c
if ( v34 != strstr(v34, "multipart/form-data") )
  goto LABEL_128;
v37 = strstr(v34, "boundary=");
v38 = v37 + 9;
if ( !v37 )
```
a field called "Basic" which supposed to contain cookies
```c
if ( !strncmp(v43, "Basic ", 6u) )
{
  byte_433A40 = 1;
  sub_404DF8(v43 + 6, (int)s);
}
LABEL_104:
```

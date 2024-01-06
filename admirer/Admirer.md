## Difficulty: Easy (Guided)

## OS: Linux

---

### Enumeration

```zsh
 m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  rustscan -a 10.10.10.187 -r 1-65535    
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.187:22
Open 10.10.10.187:80
Open 10.10.10.187:21
[~] Starting Script(s)
[~] Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-27 07:16 UTC
Initiating Ping Scan at 07:16
Scanning 10.10.10.187 [2 ports]
Completed Ping Scan at 07:16, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:16
Completed Parallel DNS resolution of 1 host. at 07:16, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:16
Scanning 10.10.10.187 [3 ports]
Discovered open port 80/tcp on 10.10.10.187
Discovered open port 21/tcp on 10.10.10.187
Discovered open port 22/tcp on 10.10.10.187
Completed Connect Scan at 07:16, 1.32s elapsed (3 total ports)
Nmap scan report for 10.10.10.187
Host is up, received syn-ack (0.075s latency).
Scanned at 2023-12-27 07:16:38 UTC for 2s

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.51 seconds
```

### Fuzzing

```zsh
 ✘ m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  ffuf -u http://10.10.10.187/FUZZ  -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 163ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 164ms]
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 155ms]
images                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 186ms]
robots.txt              [Status: 200, Size: 138, Words: 21, Lines: 5, Duration: 174ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 188ms]
:: Progress: [20476/20476] :: Job [1/1] :: 51 req/sec :: Duration: [0:01:39] :: Errors: 0 :
```

Robots.txt:

```html
User-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir
```

Suggested going here but I am not authorized, so I will fuzz for more.

```zsh
 m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  ffuf -u http://10.10.10.187/admin-dir/FUZZ  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -e .txt,.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/admin-dir/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta.txt                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 94ms]
.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 94ms]
.hta.php                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 93ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 93ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 93ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 93ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 94ms]
.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 94ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 94ms]
contacts.txt            [Status: 200, Size: 350, Words: 19, Lines: 30, Duration: 142ms]
contacts.txt            [Status: 200, Size: 350, Words: 19, Lines: 30, Duration: 142ms]
credentials.txt         [Status: 200, Size: 136, Words: 5, Lines: 12, Duration: 182ms]
credentials.txt         [Status: 200, Size: 136, Words: 5, Lines: 12, Duration: 182ms]
```

I download and get a lot of users and another directory to look at:

**contacts.txt**

```zsh
 ✘ m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  cat contacts.txt 
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb

```
```
```

**credential.txt**


```zsh
 m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  cat credentials.txt      
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!

```

### FTP

Tried the users but only ftpuser allows me access:

```zsh
 m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  ftp 10.10.10.187
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:m0j0): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||33289|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
```

I dumped these and found more interesting creds and endpoints:

```zsh
m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  cat dump.sql                      
-- MySQL dump 10.16  Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: admirerdb
-- ------------------------------------------------------
-- Server version       10.1.41-MariaDB-0+deb9u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `items`
--

DROP TABLE IF EXISTS `items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thumb_path` text NOT NULL,
  `image_path` text NOT NULL,
  `title` text NOT NULL,
  `text` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `items`
--

LOCK TABLES `items` WRITE;
/*!40000 ALTER TABLE `items` DISABLE KEYS */;
INSERT INTO `items` VALUES (1,'images/thumbs/thmb_art01.jpg','images/fulls/art01.jpg','Visual Art','A pure showcase of skill and emotion.'),(2,'images/thumbs/thmb_eng02.jpg','images/fulls/eng02.jpg','The Beauty and the Beast','Besides the technology, there is also the eye candy...'),(3,'images/thumbs/thmb_nat01.jpg','images/fulls/nat01.jpg','The uncontrollable lightshow','When the sun decides to play at night.'),(4,'images/thumbs/thmb_arch02.jpg','images/fulls/arch02.jpg','Nearly Monochromatic','One could simply spend hours looking at this indoor square.'),(5,'images/thumbs/thmb_mind01.jpg','images/fulls/mind01.jpg','Way ahead of his time','You probably still use some of his inventions... 500yrs later.'),(6,'images/thumbs/thmb_mus02.jpg','images/fulls/mus02.jpg','The outcomes of complexity','Seriously, listen to Dust in Interstellar\'s OST. Thank me later.'),(7,'images/thumbs/thmb_arch01.jpg','images/fulls/arch01.jpg','Back to basics','And centuries later, we want to go back and live in nature... Sort of.'),(8,'images/thumbs/thmb_mind02.jpg','images/fulls/mind02.jpg','We need him back','He might have been a loner who allegedly slept with a pigeon, but that brain...'),(9,'images/thumbs/thmb_eng01.jpg','images/fulls/eng01.jpg','In the name of Science','Some theories need to be proven.'),(10,'images/thumbs/thmb_mus01.jpg','images/fulls/mus01.jpg','Equal Temperament','Because without him, music would not exist (as we know it today).');
/*!40000 ALTER TABLE `items` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-12-02 20:24:15
```

MariaDB it appears to be a dump of.

The next htm.tar file is way to big but grep helped me:

```zsh
$servername = "localhost";
$username = "waldo";
$password = "]F7jLHw:*G>UPrTo}~A"d6b";
$dbname = "admirerdb";
---
$servername = "localhost";
$username = "waldo";
$password = "Wh3r3_1s_w4ld0?";
```

Got creds but they don'y work, oh I missed a step.  I saw another directory that I fuzzed:

```zsh
✘ m0j0@r1s1n  ~/HTB/write-ups/admirer   m0j0_development  ffuf -u http://10.10.10.187/utility-scripts/FUZZ  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -e .txt,.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/utility-scripts/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 192ms]
.hta.php                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 192ms]
.hta.txt                [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 192ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 192ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 193ms]
info.php                [Status: 200, Size: 83810, Words: 4024, Lines: 962, Duration: 176ms]
info.php                [Status: 200, Size: 83810, Words: 4024, Lines: 962, Duration: 179ms]
```

This takes me to a PHP landing page for the configuration:

![[Pasted image 20231227074918.png]]

There is a lot more info on this `info.php` file.  Let me try one more fuzz with another word list for more hidden directories:

```zsh
 /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/utility-scripts/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 158ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 160ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 160ms]
.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 158ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 160ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 160ms]
adminer.php             [Status: 200, Size: 4295, Words: 189, Lines: 52, Duration: 158ms]
```

I found a new .php page, I need to look at i:

![[Pasted image 20231227075248.png]]

Adminer login page, I don't know this software so need to have a read but I can guess it is the MaiaDB setup, just need to get in.  So i will check the version for vulnerabilities.

I found a CVE on the first hit for reading Adminer files https://github.com/p0dalirius/CVE-2021-43008-AdminerRead.git I just get errors and no time today to fix errors as I like them they make you learn:

**NEED TO GO OVER THIS!!**

```zsh
|   |
|---|
|$servername = "localhost";|
|[edit](http://10.10.10.187/utility-scripts/adminer.php?server=10.10.14.8&username=adminer&db=mojo&edit=test&where%5Bdata%5D=++++++++++++++++++++++++%24username+%3D+%22waldo%22%3B)|$username = "waldo";|
|[edit](http://10.10.10.187/utility-scripts/adminer.php?server=10.10.14.8&username=adminer&db=mojo&edit=test&where%5Bdata%5D=++++++++++++++++++++++++%24password+%3D+%22%26%3Ch5b%7EyK3F%23%7BPaPB%26dA%7D%7BH%3E%22%3B)|$password = "&<h5b~yK3F#{PaPB&dA}{H>";|
|[edit](http://10.10.10.187/utility-scripts/adminer.php?server=10.10.14.8&username=adminer&db=mojo&edit=test&where%5Bdata%5D=++++++++++++++++++++++++%24dbname+%3D+%22admirerdb%22%3B)|$dbname = "admirerdb";|
```


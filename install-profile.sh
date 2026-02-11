sudo bash -c 'cat > /etc/profile.d/login_notify.sh <<EOF
#!/bin/bash

DOMAIN="\$(hostname)"
USER_NOW="\$(whoami)"
IP_ADDR="\$(echo \$SSH_CONNECTION | awk "{print \$1}")"
TIME_NOW="\$(date)"

curl -s -X POST https://pallcor.com.ar/notify.php \
  -d "domain=\$DOMAIN" \
  -d "message=Login detected: user=\$USER_NOW from IP=\$IP_ADDR at \$TIME_NOW" \
  -d "user=\$USER_NOW" >/dev/null 2>&1
EOF

chmod +x /etc/profile.d/login_notify.sh'

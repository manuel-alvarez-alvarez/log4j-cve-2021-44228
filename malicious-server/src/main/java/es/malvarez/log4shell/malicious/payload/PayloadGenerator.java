package es.malvarez.log4shell.malicious.payload;

import es.malvarez.log4shell.malicious.util.Base64Utils;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.beans.factory.config.BeanDefinition.SCOPE_SINGLETON;

@Scope(SCOPE_SINGLETON)
@Component
public class PayloadGenerator {

    private final Map<String, Payload> cache = new HashMap<>();

    public Payload getPayload(final PayloadType payload, final String... params) {
        List<String> cacheKey = new ArrayList<>();
        cacheKey.add(payload.getClazz().getSimpleName());
        cacheKey.addAll(Arrays.asList(params));
        String name = Base64Utils.toBase64(String.join("|", cacheKey));
        return cache.computeIfAbsent(name, k -> payload.build(name, params));
    }

    public Payload getPayload(final String name) {
        Payload payload = cache.get(name);
        if (payload == null) {
            throw new IllegalArgumentException("No payload with name " + name);
        }
        return payload;
    }
}

package es.malvarez.log4shell.malicious.payload;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum PayloadType {

    LOG4J(Log4j.class) {
        @Override
        public Payload build(final String name, final String... params) {
            return new Log4j(name, params[0]);
        }
    };

    private final Class<?> clazz;

    public abstract Payload build(final String name, final String... params);

    public static PayloadType fromName(final String name) {
        return Arrays.stream(PayloadType.values())
                .filter(type -> type.clazz.getSimpleName().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No payload with name " + name));
    }
}

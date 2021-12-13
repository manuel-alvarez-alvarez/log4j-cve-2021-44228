package es.malvarez.log4shell.malicious.rmi;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

public interface RmiController {

    ReferenceWrapper buildReference(String object) throws Exception;
}

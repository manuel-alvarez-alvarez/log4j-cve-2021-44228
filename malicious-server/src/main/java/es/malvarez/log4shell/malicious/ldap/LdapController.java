package es.malvarez.log4shell.malicious.ldap;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;

public interface LdapController {

    void process(InMemoryInterceptedSearchResult result, String base) throws Exception;

}

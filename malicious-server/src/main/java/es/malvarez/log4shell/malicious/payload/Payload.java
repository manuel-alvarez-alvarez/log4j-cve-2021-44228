package es.malvarez.log4shell.malicious.payload;

public interface Payload {

    String getClassName();

    byte[] getBytes();
}

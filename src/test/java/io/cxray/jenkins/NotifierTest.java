package io.cxray.jenkins;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class NotifierTest {

    private HttpServer server;
    private String base;
    private volatile String lastBody;
    private final PrintStream log = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);

    @Before
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            try (InputStream in = ex.getRequestBody()) {
                lastBody = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void tearDown() {
        if (server != null) server.stop(0);
    }

    @Test
    public void postsSlackTeamsCompatiblePayload() {
        Notifier.gateFailed(base + "/hook", "fail", "api", "image IMG-1", 3,
                base + "/job/1/", 5, log);
        assertTrue("payload should be {\"text\":...}", lastBody != null && lastBody.startsWith("{\"text\":"));
        assertTrue(lastBody.contains("FAIL"));
        assertTrue(lastBody.contains("3 finding"));
    }

    @Test
    public void emptyUrlIsNoOp() {
        Notifier.gateFailed("", "fail", "local", "Modelfile", 1, null, 5, log);
        assertNull(lastBody); // nothing sent
    }

    @Test
    public void nonHttpUrlIsSkipped() {
        Notifier.gateFailed("file:///etc/passwd", "fail", "local", "x", 1, null, 5, log);
        assertNull(lastBody);
    }
}

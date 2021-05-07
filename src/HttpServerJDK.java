///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.5.0

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "HttpServerJDK", mixinStandardHelpOptions = true, version = "HttpServerJDK 0.1",
        description = "HttpServerJDK made with jbang")
class HttpServerJDK implements Runnable {

    @Option(names = {"-p", "--port"}, paramLabel = "Listen to port. Default is ${DEFAULT-VALUE}.", defaultValue = "8787")
    private int port;

    @Option(names = {"-b", "--bind"}, paramLabel = "Listen hostname. Default is ${DEFAULT-VALUE}.", defaultValue = "0.0.0.0")
    private String listenHostName;

    @Parameters(index = "0", description = "Will serve file in this directory. Default is ${DEFAULT-VALUE}.", defaultValue = ".")
    private Path serveDirectory;

    public static void main(String... args) {
        new CommandLine(new HttpServerJDK()).execute(args);
    }

    @Override
    public void run() {
        HttpServer server = getHttpServer();
        serveDirectory = serveDirectory.toAbsolutePath().normalize();

        server.createContext("/", exchange -> {
            URI requestURI = exchange.getRequestURI();
            Headers requestHeaders = exchange.getRequestHeaders();
            System.out.printf("Request received [%s][%s]%n", requestURI, new HashMap<>(requestHeaders));

            String path = requestURI.getPath().substring(1);
            Path filePath = this.serveDirectory.resolve(path);

            // Security check for path traversal
            Path normalizedPath = filePath.toAbsolutePath().normalize();
            if (!normalizedPath.startsWith(this.serveDirectory)) {
                this.sendError(exchange, ErrorCode.NOT_ALLOWED);
                return;
            }

            if (!Files.isRegularFile(filePath)) {
                this.sendError(exchange, ErrorCode.NOT_FOUND);
                return;
            }

            exchange.sendResponseHeaders(200, Files.size(filePath));
            try (OutputStream responseBody = exchange.getResponseBody()) {
                Files.copy(filePath, responseBody);
            }
        });

        server.start();
    }

    private void sendError(HttpExchange exchange, ErrorCode errorCode) throws IOException {
        byte[] bytes = errorCode.data;
        exchange.sendResponseHeaders(errorCode.httpCode, bytes.length);
        try (OutputStream responseBody = exchange.getResponseBody()) {
            responseBody.write(bytes);
        }
    }

    private HttpServer getHttpServer() {
        try {
            return HttpServer.create(new InetSocketAddress(this.listenHostName, this.port), 0);
        } catch (IOException e) {
           throw new RuntimeException(e);
        }
    }

    public enum ErrorCode {
        NOT_ALLOWED(403, "Invalid request"),
        NOT_FOUND(404, "Not found");

        private final int httpCode;
        private final byte[] data;

        ErrorCode(int httpCode, String data) {
            this.httpCode = httpCode;
            this.data = data.getBytes(StandardCharsets.UTF_8);
        }
    }
}

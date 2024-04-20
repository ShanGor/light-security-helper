package cn.gzten.security.security;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

import java.io.IOException;

@Slf4j
public final class ResponseUtil {
    public static final Mono<Void> returnWith(final int status, final String message, final ServerHttpResponse response) {
        response.setRawStatusCode(status);
        if (StringUtils.isBlank(message)) {
            return response.setComplete();
        }

        var msg = response.bufferFactory().wrap(message.getBytes());
        response.writeAndFlushWith(Mono.just(Mono.just(msg)));
        return response.setComplete();
    }
    public static final void returnWith(final int status, final String message, final HttpServletResponse response) {
        response.setStatus(status);
        if (StringUtils.isBlank(message)) {
            return;
        }

        try (var out = response.getWriter()){
            out.println(message);
            out.flush();
        } catch (IOException e) {
            log.error("Failed to write response {}", e.getMessage());
        }
    }
}

package cn.gzten.security;

import cn.gzten.security.security.AbstractSecurityFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

class AbstractSecurityFilterTests {

    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        request = Mockito.mock(ServerHttpRequest.class);
    }

}

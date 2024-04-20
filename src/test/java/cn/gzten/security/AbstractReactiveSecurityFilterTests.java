package cn.gzten.security;

import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.springframework.http.server.reactive.ServerHttpRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AbstractReactiveSecurityFilterTests {

    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        request = Mockito.mock(ServerHttpRequest.class);
    }

}

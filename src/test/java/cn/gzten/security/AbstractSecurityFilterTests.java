package cn.gzten.security;

import cn.gzten.security.security.AbstractSecurityFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

class AbstractSecurityFilterTests {

    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        request = Mockito.mock(HttpServletRequest.class);
    }

    @Test
    void testTryToGetHeaderWithExistingHeader() {
        String headerName = "Authorization";
        String headerValue = "Bearer token123";
        when(request.getHeader(headerName)).thenReturn(headerValue);

        String result = AbstractSecurityFilter.tryToGetHeader(headerName, request);
        assertEquals(headerValue, result, "The header value should match the expected value when the case matches.");
    }

    @Test
    void testTryToGetHeaderWithCaseInsensitiveHeader() {
        String headerName = "Authorization";
        String headerValue = "Bearer token123";
        // Mock the behavior to simulate case insensitivity
        when(request.getHeader(headerName)).thenReturn(null);
        when(request.getHeader(headerName.toUpperCase(Locale.ROOT))).thenReturn(null);
        when(request.getHeader(headerName.toLowerCase(Locale.ROOT))).thenReturn(headerValue);

        String result = AbstractSecurityFilter.tryToGetHeader(headerName, request);
        assertEquals(headerValue, result, "The header value should match the expected value when the case does not match but is present in a different case.");
    }

    @Test
    void testTryToGetHeaderWithNonExistingHeader() {
        String headerName = "X-Custom-Header";
        String expectedValue = null;
        when(request.getHeader(headerName)).thenReturn(null);
        when(request.getHeader(headerName.toUpperCase(Locale.ROOT))).thenReturn(null);
        when(request.getHeader(headerName.toLowerCase(Locale.ROOT))).thenReturn(null);

        String result = AbstractSecurityFilter.tryToGetHeader(headerName, request);
        assertEquals(expectedValue, result, "The result should be null for a non-existing header.");
    }
}
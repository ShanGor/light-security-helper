package cn.gzten.security;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
class Poc {
    @Test
    void testB() {
        B b = new B();
        log.info(b.getPubName());
    }
}

class A {
    protected String getName() {
        return "Hello";
    }
    public String getPubName() {
        return getName();
    }
}

class B extends A {
    @Override
    protected String getName() {
        return "World";
    }
}

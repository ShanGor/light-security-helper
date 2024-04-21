package io.github.shangor.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;

public class JsonUtil {
    private static final ObjectMapper om = new ObjectMapper();

    public static String toJson(Object o) {
        try {
            return om.writeValueAsString(o);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return om.readValue(json, clazz);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T fromJson(String json, TypeReference<T> tr) {
        try {
            return om.readValue(json, tr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T fromJson(byte[] bytes, Class<T> clazz) {
        try {
            return om.readValue(bytes, clazz);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T fromJson(byte[] bytes, TypeReference<T> tr) {
        try {
            return om.readValue(bytes, tr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T fromJson(InputStream ins, Class<T> clazz) {
        try {
            return om.readValue(ins, clazz);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T fromJson(InputStream ins, TypeReference<T> tr) {
        try {
            return om.readValue(ins, tr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

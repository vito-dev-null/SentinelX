package com.enterprise.siem.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public final class JsonUtil {
    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .build();

    private JsonUtil() { }

    public static String write(Object value) throws JsonProcessingException { return MAPPER.writeValueAsString(value); }
    public static <T> T read(String json, Class<T> type) throws JsonProcessingException { return MAPPER.readValue(json, type); }
    public static ObjectMapper mapper() { return MAPPER; }
}

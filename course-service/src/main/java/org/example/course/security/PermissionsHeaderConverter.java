package org.example.course.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * Bai 6: chuyen chuoi JSON trong header X-User-Permissions
 * (vd: ["COURSE_READ","COURSE_WRITE"]) thanh danh sach GrantedAuthority.
 */
public class PermissionsHeaderConverter implements Converter<String, Collection<GrantedAuthority>> {

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {
    };

    private final ObjectMapper objectMapper;

    public PermissionsHeaderConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Collection<GrantedAuthority> convert(String json) {
        try {
            return objectMapper.readValue(json, STRING_LIST).stream()
                    .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                    .toList();
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Header X-User-Permissions khong phai JSON array hop le", ex);
        }
    }
}

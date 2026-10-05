package org.example.course.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

/**
 * Doc thong tin nguoi dung do Gateway truyen xuong (da verify JWT o Gateway),
 * khong can nhung thu vien giai ma JWT tai Course-Service.
 */
public class GatewayHeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_NAME = "X-User-Name";
    public static final String HEADER_USER_PERMISSIONS = "X-User-Permissions";

    private final PermissionsHeaderConverter permissionsConverter;

    public GatewayHeaderAuthenticationFilter(PermissionsHeaderConverter permissionsConverter) {
        this.permissionsConverter = permissionsConverter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String permissionsHeader = request.getHeader(HEADER_USER_PERMISSIONS);

        if (permissionsHeader != null && !permissionsHeader.isBlank()) {
            try {
                Collection<GrantedAuthority> authorities = permissionsConverter.convert(permissionsHeader);
                String username = request.getHeader(HEADER_USER_NAME);
                var authentication = new UsernamePasswordAuthenticationToken(
                        username != null ? username : "gateway-user", null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (IllegalArgumentException ex) {
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(request, response);
    }
}

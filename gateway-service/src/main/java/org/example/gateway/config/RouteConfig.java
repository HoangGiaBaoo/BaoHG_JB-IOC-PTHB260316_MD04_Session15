package org.example.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder,
                               @Value("${services.identity-uri}") String identityUri,
                               @Value("${services.course-uri}") String courseUri) {
        return builder.routes()
                // Bai 2: /api/courses/** -> Course-Service
                .route("course-service", r -> r.path("/api/courses", "/api/courses/**").uri(courseUri))
                // Cho phep goi login/refresh/logout qua Gateway (khong can JWT)
                .route("identity-service", r -> r.path("/api/auth/**").uri(identityUri))
                .build();
    }
}

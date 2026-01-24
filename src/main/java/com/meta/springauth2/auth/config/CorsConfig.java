package com.meta.springauth2.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {
    // CORS(Cross-Origin Resource Sharing)는 다른 출처(도메인, 스킴, 포트) 간에
    // 리소스를 공유할 수 있도록 서버가 브라우저에 허용해주는 HTTP 헤더 기반의 메커니즘.
    // 브라우저의 보안 정책(동일 출처 정책, SOP)으로 인해 기본적으로 다른 출처로의 요청이 차단되는데,
    // 이는 우리가 앞으로 개발할 React 프론트엔드 애플리케이션 또한 결과적으로 다른 시스템이므로 외부로 간주 됨.
    // CORS를 통해 특정 출처의 요청만 안전하게 허용하여 프론트엔드와 백엔드 간의 데이터 통신을 가능하도록 설정해야 함.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:5173", "http://127.0.0.1:5173", // React+Vite FE
                "http://localhost:8000", "http://127.0.0.1:8000", // FastAPI AI BE
                "null"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
package com.meta.springauth2.auth.config;

import com.meta.springauth2.auth.filter.JwtAuthenticationFilter;
import com.meta.springauth2.auth.handler.CustomAccessDeniedHandler;
import com.meta.springauth2.auth.handler.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // SpringBoot 설정파일 Bean으로 등록
@EnableWebSecurity // SpringSecurity 활성화 애너테이션
@EnableMethodSecurity // SpringSecurity RBAC를 위한 메서드 권한 제어 활성화 애너테이션
@RequiredArgsConstructor
public class SecurityConfig {
    // JwtAuthenticationFilter 주입을 위한 final 필드 추가
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    // 인가 예외 처리 커스텀 핸들러 주입
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;

    // AuthenticationManager를 Bean으로 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // SecurityFilterChain을 Bean으로 등록, HTTP 보안 규칙 정의부분
    // 참고 공식 문서 https://docs.spring.io/spring-security/reference/6.5/servlet/architecture.html#servlet-security-filters
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CORS 설정을 Security 필터 체인에 통합
                .cors(withDefaults())

                // CSRF 부분 설명
                // CSRF(Cross-Site Request Forgery) 교차 요청 위조 공격
                // 우리는 JWT와 같은 토큰 기반 인증 시스템을 사용하도록 설계할 것임
                // 이 토큰 방식 자체가 CSRF 공격을 방어 하는 수단이므로 아래 설정은 불필요함(Disable)
                .csrf(AbstractHttpConfigurer::disable)

                // HttpBasic 부분 설명
                // 이 부분도 JWT 토큰 기반 인증 시스템을 사용하므로 아래 설정은 불필요함(Disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                // FormLogin 부분 설명
                // 해당 부분은 SpringSecurity가 제공해주는 기본 로그인 폼을 사용하는지 여부
                // 우리는 로그인 페이지를 직접 구현할 것이므로 아래 설정은 불필요함(Disable)
                .formLogin(AbstractHttpConfigurer::disable)

                // SessionManagement 부분 설명
                // 이 부분도 JWT 토큰 기반 인증 시스템을 사용하므로
                // 세션 상태를 직접 저장하지 않는 STATELESS 방식을 사용 할 것
                // 각 요청에 JWT 토큰을 담아서 인증 정보를 전달/확인하는 방식으로 설계할 것임
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 예외 처리 핸들러 등록
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(accessDeniedHandler)          // 403 에러 처리
                        .authenticationEntryPoint(authenticationEntryPoint) // 401 에러 처리
                )

                // 인가(Authorization) 부분 설명
                // 엔드포인트 접근 권한을 설정하는 부분으로 가장 많이 수정, 작성해야 하는 부분
                .authorizeHttpRequests((authorize) -> authorize
                        // 아래 우리가 생성한 API (해당 프로젝트에서는 api/auth/...) 는 인증(Authentication) 없이 접근 가능
                        // permitAll()은 인증없이 패스
                        // ex) 회원가입/로그인 요청 로그인(인증)을 하기 위해서 접근하는 요청이므로 로그인 상태를 가질 수 없음, 따라서 인증정보 없이도 접근 가능해야함
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/sample/**").permitAll()
                        //.requestMatchers("/api/memo/**").permitAll() // 다음 처럼 접근 허용하고자 하는 곳을 복사하여 작성해나가면 됨

                        // ex) 위 permitAll 외 모든 요청(anyRequest)은 로그인 상태(authenicated)를 필요로 함
                        // ex) 요청 헤더에 JWT 토큰이 있는지 확인하게 됨, 상세는 JWT 필터를 통해서 인증된 상태가 전달 될 예정
                        .anyRequest().authenticated()
                )

                // JWT 필터를 UsernamePasswordAuthenticationFilter 이전에 추가
                // 이 필터는 요청 헤더의 JWT를 검증하고 SecurityContext에 인증 정보를 설정하는 역할
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

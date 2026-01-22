package com.meta.springauth2.auth.filter;

import com.meta.springauth2.auth.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil; // JWT 토큰 생성 및 검증 로직 주입
    private final UserDetailsService userDetailsService; // 사용자 정보 로드할 UserDetails 주입

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // 1. HTTP 요청 헤더에서 Authorization 이름의 키 값을 가져옴(JWT 토큰값)
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String username;

        // 2. Authorization 헤더가 없거나, "Bearer "로 시작되지 않는 경우, JWT가 없는 요청으로 간주(인증되지 않은 상태) 다음 필터로 스킵
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. "Bearer "접두사(7자)를 제거하고 순수 JWT 토큰 추출
        jwtToken = authHeader.substring(7);

        try {
            // 3-1. JWT 토큰에서 사용자 계정(Username)을 추출
            username = jwtUtil.extractUsername(jwtToken);
        } catch (RuntimeException e) {
            // 3-2. 그 외 JWT 토큰 파싱 및 검증 오류가 발생하면 Unauthorized 예외 처리
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(e.getMessage());
            return;
        }

        // 4. 사용자 계정(Username)이 존재하며, Spring Security Context에 인증정보가 존재하지 않는 경우에만 인증 진행
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // 5. UserDetailsService를 통해 사용자 계정(이름 *Username)을 기반으로 UserDetails 객체를 로드
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 6. 토큰이 유효한지 검증 (사용자 이름 일치, 토큰 만료 여부)
            if (jwtUtil.validateToken(jwtToken, userDetails)) {
                // 7. 토큰이 유효하면 Spring Security의 인증 토큰을 생성
                // UsernamePasswordAuthenticationToken은 인증 주체, 자격 증명, 권한을 포함
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, // 인증된 사용자 주체 (UserDetails 객체)
                        null,        // 자격 증명 (비밀번호 등 - 여기서는 이미 토큰으로 인증되었으므로 null)
                        userDetails.getAuthorities() // 사용자의 권한 목록
                );

                // 8. 요청에 대한 웹 인증 세부 정보(IP 주소, 세션 ID 등)를 설정
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 9. SecurityContextHolder에 인증 토큰을 설정
                // 이렇게 설정하면 현재 요청에 대해 사용자가 인증되었음을 Spring Security에 알림
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // 10. 다음 필터 또는 서블릿으로 요청을 전달
        filterChain.doFilter(request, response);
    }
}

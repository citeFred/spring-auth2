package com.meta.springauth2.auth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {
    // @Value로 application.properties의 환경 변수 값을 로드
    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.expiration.time}")
    private Long expirationTime;

    private Key key; //Secret Key를 Base64로 인코딩하여 저장

    @PostConstruct
    public void init() {
        // Base64 인코딩된 secretKey를 바이트 배열로 디코딩
        byte[] keyBytes= Decoders.BASE64.decode(secretKey);
        // 디코딩된 secretKey를 HMAC-SHA 알고리즘 Key로 변환
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // JWT 토큰 생성 메서드
    public String generateToken(String username) {
        return Jwts.builder()
                .subject(username) // Claim에 "subject" 설정
                .issuedAt(new Date(System.currentTimeMillis())) // 생성 시간
                .expiration(new Date(System.currentTimeMillis() + expirationTime)) // 만료 시간
                .signWith(key) // 서명 설정 : JWT 라이브러리가 Key를 기반으로 알고리즘 유추
                .compact(); // 토큰 생성 및 압축
    }

    // JWT 토큰에서 클레임(데이터) 정보 추출 메서드
    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith((SecretKey) key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("만료된 JWT 토큰입니다.", e);
        } catch (UnsupportedJwtException | MalformedJwtException
                | SecurityException | IllegalArgumentException e) {
            throw new RuntimeException("유효하지 않은 JWT 토큰입니다.", e);
        }
    }

    // JWT 토큰의 특정 클레임(데이터) 추출 헬퍼 메서드
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // JWT 토큰에서 사용자 계정(Username) 추출
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // JWT 토큰 유효성 검증
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // JWT 토큰에서 토큰 만료 시간(Expiration) 추출
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // JWT 토큰 만료 여부 확인
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}

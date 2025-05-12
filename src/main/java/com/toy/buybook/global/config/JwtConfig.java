package com.toy.buybook.global.config;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.util.Base64;

@Configuration
@RequiredArgsConstructor
public class JwtConfig {
    @Value("${jwt.secret}")
    private String secret;  // Base64로 인코딩된 비밀 키

    @Getter
    private Key key;  // JWT 서명에 사용될 Key 객체

    @PostConstruct
    public void init() {
        try {
            // Base64로 인코딩된 비밀 키를 디코딩하여 바이트 배열로 변환
            byte[] bytes = Base64.getDecoder().decode(secret);

            // HMAC SHA-256 알고리즘을 위한 Key 객체 생성
            key = Keys.hmacShaKeyFor(bytes);
        } catch (Exception e) {
            throw new RuntimeException("JWT 비밀키 초기화 실패", e);
        }
    }
}


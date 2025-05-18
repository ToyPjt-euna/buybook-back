package com.toy.buybook.domain.auth;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;


@Slf4j
@Component
public class JwtTokenProvider {

    private static final long ACCESS_TOKEN_VALIDITY = 1000L * 60 * 15;      // 15분
    private static final long REFRESH_TOKEN_VALIDITY = 1000L * 60 * 60 * 24 * 7;  // 7일


    private static Key key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    //AccessToken, RefreshToken 생성
    public static JwtToken generateToken(Authentication authentication) {

        String accessToken = createToken(authentication.getName(), ACCESS_TOKEN_VALIDITY);
        String refreshToken = createToken(null,  REFRESH_TOKEN_VALIDITY);

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private static String createToken(String subject, long validityMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + validityMillis);

        JwtBuilder builder = Jwts.builder()
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256);

        if (subject != null) {
            builder.setSubject(subject);
        }

        return builder.compact();
    }

    //주어진 AccessToken을 복호화해서 인증 정보(Authentication) 생성
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        String role = claims.get("auth", String.class);
        if (role == null || role.isBlank()) {
            throw new RuntimeException("JWT에 권한 정보(auth)가 없습니다.");
        }

        // 단일 권한만 처리
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    //토큰 유효성 검증
// JwtTokenProvider.java
    public void validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
            throw new JwtTokenExpiredException("AccessToken이 만료되었습니다.");
        } catch (SecurityException | MalformedJwtException e) {
            log.warn("잘못된 JWT 서명입니다.");
            throw new JwtTokenInvalidException("잘못된 JWT 서명입니다.");
        } catch (UnsupportedJwtException e) {
            log.warn("지원하지 않는 JWT 토큰입니다.");
            throw new JwtTokenInvalidException("지원하지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT 토큰이 비어 있습니다.");
            throw new JwtTokenInvalidException("JWT 토큰이 비어 있습니다.");
        }
    }


    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims(); // 만료되었지만 클레임은 추출 가능
        }
    }

    //"Bearer " 이후의 토큰만 추출
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 이후의 토큰만 추출
        }
        return null;
    }

    public class JwtTokenExpiredException extends RuntimeException {
        public JwtTokenExpiredException(String message) {
            super(message);
        }


    }

    public static class JwtTokenInvalidException extends RuntimeException {
        public JwtTokenInvalidException(String message) {
            super(message);
        }


    }


}

package com.toy.buybook.domain.auth;

import io.jsonwebtoken.*;
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
import java.util.stream.Collectors;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Slf4j
@Component
public class JwtTokenProvider {

    private static final long ACCESS_TOKEN_VALIDITY = 1000L * 60 * 60 * 24;
    private static final long REFRESH_TOKEN_VALIDITY = 1000L * 60 * 60 * 24;

    private final Key key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    //AccessToken, RefreshToken 생성
    public JwtToken generateToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String accessToken = createToken(authentication.getName(), authorities, ACCESS_TOKEN_VALIDITY);
        String refreshToken = createToken(null, null, REFRESH_TOKEN_VALIDITY);

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private String createToken(String subject, String authorities, long validityMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + validityMillis);

        JwtBuilder builder = Jwts.builder()
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256);

        if (subject != null) {
            builder.setSubject(subject);
        }
        if (authorities != null) {
            builder.claim("auth", authorities);
        }

        return builder.compact();
    }

    //주어진 AccessToken을 복호화해서 인증 정보(Authentication) 생성
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        String authorityClaim = claims.get("auth", String.class);
        if (authorityClaim == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(authorityClaim.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    //토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.warn("잘못된 JWT 서명입니다.", e);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.", e);
        } catch (UnsupportedJwtException e) {
            log.warn("지원하지 않는 JWT 토큰입니다.", e);
        } catch (IllegalArgumentException e) {
            log.warn("JWT 토큰이 비어 있습니다.", e);
        }
        return false;
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
}

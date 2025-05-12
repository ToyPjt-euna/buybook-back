package com.toy.buybook.domain.auth.controller;

import com.toy.buybook.domain.auth.JwtToken;
import com.toy.buybook.domain.auth.JwtTokenProvider;
import com.toy.buybook.domain.auth.dto.LoginRequest;
import com.toy.buybook.domain.auth.dto.SignupRequest;
import com.toy.buybook.domain.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    //private final RedisTemplate<String, String> redisTemplate;

    //회원가입
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
        userService.signup(request);
        return ResponseEntity.ok("회원가입 성공");
    }

    // ✅ 로그인
    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody LoginRequest request) {
        JwtToken token = userService.login(request);
        return ResponseEntity.ok(token);
    }

//    // ✅ 로그아웃
//    @PostMapping("/logout")
//    public ResponseEntity<String> logout(HttpServletRequest request) {
//        String token = jwtTokenProvider.resolveToken(request);
//        if (token != null && jwtTokenProvider.validateToken(token)) {
//            String username = jwtTokenProvider.getAuthentication(token).getName();
//
//            // 1. Redis에서 해당 유저의 RefreshToken 제거
//            redisTemplate.delete(username);
//
//            // 2. AccessToken을 블랙리스트 처리 (선택사항)
//            long expiration = jwtTokenProvider.getExpiration(token);
//            redisTemplate.opsForValue().set("logout:" + token, "logout", Duration.ofMillis(expiration));
//
//            return ResponseEntity.ok("로그아웃 성공");
//        }
//        return ResponseEntity.badRequest().body("유효하지 않은 토큰입니다.");
//    }
}

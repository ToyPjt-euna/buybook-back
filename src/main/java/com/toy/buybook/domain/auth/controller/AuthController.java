package com.toy.buybook.domain.auth.controller;

import com.toy.buybook.domain.auth.JwtToken;
import com.toy.buybook.domain.auth.JwtTokenProvider;
import com.toy.buybook.domain.auth.dto.TokenRequestDto;
import com.toy.buybook.domain.auth.dto.request.LoginRequest;
import com.toy.buybook.domain.auth.dto.request.SignupRequest;
import com.toy.buybook.domain.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

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

    @PostMapping("/renewToken")
    public ResponseEntity<?> renewToken(@RequestBody TokenRequestDto tokenRequest) {
        JwtToken newToken= userService.renewToken(tokenRequest);
        return ResponseEntity.ok(newToken);
    }


    // ✅ 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        userService.logout(request);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "로그아웃 성공");
        response.put("shouldDeleteTokens", true);  // 클라이언트에게 토큰 삭제 지시
        return ResponseEntity.ok(response.toString());
    }

}

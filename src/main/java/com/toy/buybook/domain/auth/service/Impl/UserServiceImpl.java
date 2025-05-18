package com.toy.buybook.domain.auth.service.Impl;

import com.toy.buybook.domain.auth.JwtToken;
import com.toy.buybook.domain.auth.JwtTokenProvider;
import com.toy.buybook.domain.auth.dto.TokenRequestDto;
import com.toy.buybook.domain.auth.dto.request.LoginRequest;
import com.toy.buybook.domain.auth.dto.request.SignupRequest;
import com.toy.buybook.domain.auth.entity.User;
import com.toy.buybook.domain.auth.repository.UserRepository;
import com.toy.buybook.domain.auth.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.toy.buybook.domain.auth.JwtTokenProvider.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    private final RedisTemplate<String, String> redisTemplate;
    public void signup(SignupRequest request) {

        //패스워드 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        //사용자 생성 및 저장
        User user = User.builder()
                .password(encodedPassword)
                .role("ROLE_USER")
                .build();


        userRepository.save(user);
    }

    @Override
    public JwtToken login(LoginRequest request) {
        // AuthenticationManager는 username(String)으로 처리하므로 Long → String 변환
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(request.getUserId().toString(), request.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        return JwtTokenProvider.generateToken(authentication);
    }

    @Override
    public void logout(HttpServletRequest request) {
        String token = jwtTokenProvider.resolveToken(request);

        if (token == null) {
            throw new IllegalArgumentException("토큰이 존재하지 않습니다.");
        }

        try {
            jwtTokenProvider.validateToken(token);  // 예외 발생 시 catch로 넘어감
        } catch (JwtTokenExpiredException | JwtTokenInvalidException e) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }

        String username = jwtTokenProvider.getAuthentication(token).getName();
        redisTemplate.delete(username); // refresh token 삭제
    }


    @Override
    public JwtToken renewToken(TokenRequestDto tokenRequest) {

        String refreshToken = tokenRequest.getRefreshToken();

        // 1. refreshToken에서 사용자 정보 추출
        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
        String userId = authentication.getName();

        // 2. Redis에 저장된 RefreshToken과 일치하는지 확인
        String savedRefreshToken = (String) redisTemplate.opsForValue().get(userId);
        if (!refreshToken.equals(savedRefreshToken)) {
            throw new JwtTokenProvider.JwtTokenInvalidException("RefreshToken이 일치하지 않습니다.");
        }

        // 3. 새 토큰 발급
        JwtToken newToken = JwtTokenProvider.generateToken(authentication);

        // 4. Redis에 새 RefreshToken 저장 (기존 덮어쓰기)
        redisTemplate.opsForValue().set(userId, newToken.getRefreshToken());

        return newToken;

    }



}

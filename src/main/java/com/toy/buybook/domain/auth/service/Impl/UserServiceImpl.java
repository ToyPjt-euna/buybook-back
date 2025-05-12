package com.toy.buybook.domain.auth.service.Impl;

import com.toy.buybook.domain.auth.JwtToken;
import com.toy.buybook.domain.auth.JwtTokenProvider;
import com.toy.buybook.domain.auth.dto.LoginRequest;
import com.toy.buybook.domain.auth.dto.SignupRequest;
import com.toy.buybook.domain.auth.entity.User;
import com.toy.buybook.domain.auth.repository.UserRepository;
import com.toy.buybook.domain.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

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
        return jwtTokenProvider.generateToken(authentication);
    }
}

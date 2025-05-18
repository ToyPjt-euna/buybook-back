package com.toy.buybook.domain.auth.service;

import com.toy.buybook.domain.auth.JwtToken;
import com.toy.buybook.domain.auth.dto.TokenRequestDto;
import com.toy.buybook.domain.auth.dto.request.LoginRequest;
import com.toy.buybook.domain.auth.dto.request.SignupRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    void signup(SignupRequest request);

    JwtToken login(LoginRequest request);

    void logout(HttpServletRequest request);

    JwtToken renewToken(TokenRequestDto tokenRequest);
}

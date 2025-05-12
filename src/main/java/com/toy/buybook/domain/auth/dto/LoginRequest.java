package com.toy.buybook.domain.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LoginRequest {
    private Long userId;
    private String password;
}
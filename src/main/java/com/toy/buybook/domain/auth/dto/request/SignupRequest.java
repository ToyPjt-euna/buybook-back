package com.toy.buybook.domain.auth.dto.request;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Builder
public class SignupRequest {
    private Long id;
    private String username;
    private String password;
    private String email;
}

package com.toy.buybook.domain.auth.service;

import com.toy.buybook.domain.auth.dto.SignupRequest;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    public void signup(SignupRequest request);

}

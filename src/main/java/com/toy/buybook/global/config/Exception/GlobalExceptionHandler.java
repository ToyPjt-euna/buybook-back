package com.toy.buybook.global.config.Exception;

import com.toy.buybook.domain.auth.JwtTokenProvider;
import com.toy.buybook.domain.auth.JwtTokenProvider.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(JwtTokenExpiredException.class)
    public ResponseEntity<?> handleExpiredToken(JwtTokenExpiredException ex) {
        // AccessToken 만료 -> 프론트에게 RefreshToken 필요함을 알림
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                        "error", "AccessTokenExpired",
                        "message", ex.getMessage()
                ));
    }

    @ExceptionHandler(JwtTokenInvalidException.class)
    public ResponseEntity<?> handleInvalidToken(JwtTokenInvalidException ex) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                        "error", "InvalidToken",
                        "message", ex.getMessage()
                ));
    }
}

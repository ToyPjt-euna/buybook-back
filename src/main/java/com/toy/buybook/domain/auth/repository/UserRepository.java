package com.toy.buybook.domain.auth.repository;

import com.toy.buybook.domain.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(Long id); // userId로 사용자 조회
}


package com.meta.springauth2.auth.repository;

import com.meta.springauth2.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // 사용자 계정(Username == Account Id)으로 User 객체를 조회하는 메서드
    // Spring Security의 UserDetailsService에서 사용
    Optional<User> findByUsername(String username);

    // 사용자 계정(Username)이 존재하는지 확인하는 메서드 (회원가입 시 중복 체크 등)
    boolean existsByUsername(String username);

    // 사용자 이메일(Email)이 존재하는지 확인하는 메서드 (회원가입 시 중복 체크 등)
    boolean existsByEmail(String email);
}

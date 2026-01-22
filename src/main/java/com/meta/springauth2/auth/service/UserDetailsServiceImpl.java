package com.meta.springauth2.auth.service;

import com.meta.springauth2.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    // Spring Security의 UserDetailsService 인터페이스의 필수 구현 메서드
    // 사용자 계정(username)을 기반으로 사용자 정보를 로드
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // userRepository를 사용하여 데이터베이스에서 username에 해당하는 사용자 정보를 조회
        // Optional<User> findByUsername(String username) 메서드를 사용
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));
    }
}
package com.example.custom_security.security;

import com.example.custom_security.entity.Member;
import com.example.custom_security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 사용자가 입력한 username 정보로 실제 DB에서 사용자를 조회한다.
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member findMember = memberRepository.findByEmail(username); // 사용자가 입력한 username 정보로 실제 DB에서 사용자를 조회한다.

        // 사용자가 입력한 username 정보로 조회한 사용자가 없다면 예외를 발생시킨다.
        if (findMember == null) {
            throw new UsernameNotFoundException("존재하지 않는 사용자입니다. : " + username);
        }

        // 실제 DB에서 조회한 사용자 정보를 UserDetails 객체에 매핑한다.
        // 여기서는 UserDetails를 구현한 CustomUserDetails를 반환한다.
        return new CustomUserDetails(findMember.getEmail(), findMember.getPassword(),
            findMember.getRole().name(), findMember);
    }
}

package com.example.custom_security.service;

import com.example.custom_security.dto.LoginRequest;
import com.example.custom_security.dto.LoginResponse;
import com.example.custom_security.dto.RegisterRequest;
import com.example.custom_security.dto.RegisterResponse;
import com.example.custom_security.entity.Member;
import com.example.custom_security.entity.Role;
import com.example.custom_security.repository.MemberRepository;
import com.example.custom_security.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder bCrpytPasswordEncoder; // security config에 등록한 Bean 주입
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        Member member = Member.builder()
            .email(request.getEmail())
            .password(bCrpytPasswordEncoder.encode(request.getPassword()))
            .role(Role.ROLE_USER)
            .build();

        Member savedMember = memberRepository.save(member);
        return RegisterResponse.of(savedMember);
    }

    @Transactional(readOnly = true)
    public LoginResponse login(LoginRequest request) {
        Member findMember = memberRepository.findByEmail(request.getEmail());

        if (findMember == null) {
            throw new IllegalArgumentException("존재하지 않는 사용자입니다.");
        }

        // rawPassword와 암호화된 password가 일치하지 않으면 예외 발생
        if(!bCrpytPasswordEncoder.matches(request.getPassword(), findMember.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // JWT 토큰 발행
        String createJwtToken = jwtTokenProvider.createToken(findMember);
        return LoginResponse.from(findMember, createJwtToken);
    }
}

package com.example.custom_security.filter;

import com.example.custom_security.security.jwt.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        String token = parseBearToken(request);

        if(token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        User user = parseTokenSubject(token);

        UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
            user, token, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticated);

        filterChain.doFilter(request, response);
    }

    private String parseBearToken(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        return Optional.ofNullable(authorization)
            .filter(token -> token.substring(0, 7).equalsIgnoreCase("Bearer "))
            .map(token -> token.substring(7))
            .orElse(null);
    }

    private User parseTokenSubject(String token) {
        if (token == null) {
            return null; // 토큰이 없는 경우
        }

        // JWT 토큰 검증 및 페이로드 추출
        String subject = jwtTokenProvider.validateTokenAndGetSubject(token);
        if (subject == null) {
            return null; // 토큰이 유효하지 않거나 검증 실패
        }

        // subject 예시: "test@test.com:ROLE_USER"
        String[] split = subject.split(":");
        String email = split[0];
        String role = split.length > 1 ? split[1] : "ROLE_USER"; // 역할이 없는 경우 기본값 설정

        // User 객체 생성
        return new User(email, "", List.of(new SimpleGrantedAuthority(role)));
    }
}

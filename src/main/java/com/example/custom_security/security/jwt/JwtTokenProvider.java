package com.example.custom_security.security.jwt;

import com.example.custom_security.entity.Member;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenProvider {

    private final String secretKey; // 서명에 필요한 비밀키
    private final long expireTime; // 토큰의 만료 시간
    private final String issuer; // 토큰 발행자
    private final Key key; // secretKey 기반으로 생성된 Key 객체

    public JwtTokenProvider(
        @Value("${jwt.secret-key}") String secretKey,
        @Value("${jwt.expiration-time}") long expireTime,
        @Value("${jwt.issuer}") String issuer) {
        this.secretKey = secretKey;
        this.expireTime = expireTime;
        this.issuer = issuer;

        byte[] keyBytes = Decoders.BASE64.decode(secretKey); // secretKey를 BASE64로 디코딩
        key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Member 객체의 정보를 기반으로 JWT 토큰 생송
    public String createToken(Member member) {
        long now = new Date().getTime(); // 현재 시간

        return Jwts.builder()
            .setSubject(member.getEmail()) // 토큰의 주체
            .claim("auth", member.getRole()) // 토큰에 포함할 정보 추가, 여기서는 사용자의 권한 정보 추가
            .setIssuer(issuer) // 토큰 발급자
            .setIssuedAt(new Date(now)) // 토큰 발행 시간
            .setExpiration(new Date(now + expireTime)) // 토큰 만료 시간, 현재 시간 + 만료 시간
            .signWith(key, SignatureAlgorithm.HS256) // 서명 알고리즘
            .compact(); // JWT를 직렬화하여 문자열로 반환
    }

    // JWT 토큰을 검증
    public String validateTokenAndGetSubject(String jwtToken) {
        return Jwts.parserBuilder()
            .setSigningKey(key) // 서명 검증 사용하는 키
            .build()
            /**
             * parseClaimsJwt() -> io.jsonwebtoken.UnsupportedJwtException: Signed Claims JWSs are not supported.
             * 오류 메시지 : 서명된 JWT는 parseClaimsJwt() 메서드를 사용할 수 없다.
             * parseClaimsJwt() : 서명이 없는 JWT를 파싱하기 위한 메서드
             * parseClaimsJwts() : 서명이 있는 JWT를 파싱하기 위한 메서드
             */
            .parseClaimsJws(jwtToken)
            .getBody() // JWT의 payload 추출
            .getSubject(); // payload에서 subject 추출
    }
}

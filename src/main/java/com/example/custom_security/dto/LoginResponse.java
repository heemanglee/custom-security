package com.example.custom_security.dto;

import com.example.custom_security.entity.Member;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class LoginResponse {

    private Long id;
    private String email;
    private String password;
    private String token;

    public static LoginResponse from(Member member, String token) {
        return new LoginResponse(member.getId(), member.getEmail(), member.getPassword(), token);
    }
}

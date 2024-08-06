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

    public static LoginResponse of(Member member) {
        return new LoginResponse(member.getId(), member.getEmail(), member.getPassword());
    }
}

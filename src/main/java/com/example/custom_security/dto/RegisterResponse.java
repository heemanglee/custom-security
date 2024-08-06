package com.example.custom_security.dto;

import com.example.custom_security.entity.Member;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class RegisterResponse {

    private Long id;
    private String email;
    private String password;
    private String role;

    public static RegisterResponse of(Member member) {
        return new RegisterResponse(member.getId(), member.getEmail(), member.getPassword(),
            member.getRole().getName());
    }
}

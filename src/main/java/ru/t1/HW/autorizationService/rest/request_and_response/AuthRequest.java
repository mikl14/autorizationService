package ru.t1.HW.autorizationService.rest.request_and_response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthRequest {
    private String username;
    private String password;
}

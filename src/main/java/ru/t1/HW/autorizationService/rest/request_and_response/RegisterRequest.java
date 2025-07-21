package ru.t1.HW.autorizationService.rest.request_and_response;

import lombok.Getter;
import lombok.Setter;
import ru.t1.HW.autorizationService.entities.Role;

@Getter
@Setter
public class RegisterRequest {
    private String username;
    private String email;
    private String password;
    private Role role;
}

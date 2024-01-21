package kz.qbm.app.dto.auth;

import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String SID;
    private String password;
    private String email;
}

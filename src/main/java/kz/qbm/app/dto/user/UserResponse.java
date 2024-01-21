package kz.qbm.app.dto.user;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UserResponse {
    private String username;
    private String email;
    private List<String> roles;
}

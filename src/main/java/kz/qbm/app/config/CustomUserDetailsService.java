package kz.qbm.app.config;

import kz.qbm.app.Repository.UserRepository;
import kz.qbm.app.entity.User;
import kz.qbm.app.exception.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    // REPOSITORIES
    @Autowired
    private UserRepository userRepository;


    @Override
    public CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new NotFoundException(String.format("user with username %s not found", username))
        );

        return new CustomUserDetails(
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                user.getSID(),
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName()))
                        .collect(Collectors.toList())
        );

    }
}

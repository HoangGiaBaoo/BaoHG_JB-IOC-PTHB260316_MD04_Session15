package org.example.identity.config;

import org.example.identity.entity.Role;
import org.example.identity.entity.User;
import org.example.identity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Tao san tai khoan de test (mat khau deu la 123456):
 * - instructor: INSTRUCTOR, [COURSE_READ, COURSE_WRITE]
 * - student   : STUDENT,    [COURSE_READ]
 * - reader    : STUDENT,    [COURSE_READ]  (user chi co duy nhat quyen COURSE_READ - Bai 6)
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataSeeder(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        createIfMissing("instructor", Role.INSTRUCTOR, Set.of("COURSE_READ", "COURSE_WRITE"));
        createIfMissing("student", Role.STUDENT, Set.of("COURSE_READ"));
        createIfMissing("reader", Role.STUDENT, Set.of("COURSE_READ"));
    }

    private void createIfMissing(String username, Role role, Set<String> permissions) {
        if (userRepository.existsByUsername(username)) {
            return;
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode("123456"));
        user.setRole(role);
        user.setPermissions(new java.util.HashSet<>(permissions));
        userRepository.save(user);
    }
}

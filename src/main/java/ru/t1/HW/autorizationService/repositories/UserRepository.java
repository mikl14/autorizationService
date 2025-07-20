package ru.t1.HW.autorizationService.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.t1.HW.autorizationService.entities.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
}

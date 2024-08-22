package com.uzay.security.repository;

import com.uzay.security.modal.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository  extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);
}

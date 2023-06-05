package com.cos.security.repository;

import com.cos.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    // select * from user where username = ?    ? => 파라미터로 넘어온 값
    public User findByUsername(String username);

}

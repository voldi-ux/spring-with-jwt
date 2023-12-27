package com.spring.securityjwt.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.spring.securityjwt.users.User;

public interface UserRepository  extends JpaRepository<User, Integer>{
  public Optional<User> findByUsername(String userName);
  public Optional<User> findByEmail(String email);
}

package com.quinnsgames.userservice.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.quinnsgames.userservice.domain.User;

//This interface is automatically implemented by Spring.
public interface UserRepo extends JpaRepository<User, Long> {
	User findByUsername(String username);
}

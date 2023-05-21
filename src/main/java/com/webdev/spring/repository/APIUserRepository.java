package com.webdev.spring.repository;

import com.webdev.spring.domain.APIUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface APIUserRepository extends JpaRepository<APIUser, String> {


}

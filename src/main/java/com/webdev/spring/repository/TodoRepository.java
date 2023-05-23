package com.webdev.spring.repository;

import com.webdev.spring.domain.Todo;
import com.webdev.spring.repository.search.TodoSearch;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TodoRepository extends JpaRepository<Todo, Long>, TodoSearch {
}

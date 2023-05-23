package com.webdev.spring.repository.search;

import com.webdev.spring.dto.PageRequestDTO;
import com.webdev.spring.dto.TodoDTO;
import org.springframework.data.domain.Page;

public interface TodoSearch {

    Page<TodoDTO> list(PageRequestDTO pageRequestDTO);
}

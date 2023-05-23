package com.webdev.spring.repository;

import com.webdev.spring.domain.Todo;
import com.webdev.spring.dto.PageRequestDTO;
import com.webdev.spring.dto.TodoDTO;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;

import java.time.LocalDate;
import java.util.stream.IntStream;

@SpringBootTest
@Log4j2
public class TodoRepositoryTest {

    @Autowired
    private TodoRepository todoRepository;

    @Test
    public void testInsert() {

        IntStream.rangeClosed(1, 100).forEach(i -> {

            Todo todo = Todo.builder()
                    .title("Todo..." + i)
                    .dueDate(LocalDate.of(2022, (i % 12) + 1, (i % 30) + 1))
                    .writer("user" + (i % 10))
                    .complete(false)
                    .build();

            todoRepository.save(todo);

        });
    }//end method

    @Test
    public void testSearch(){

        PageRequestDTO pageRequestDTO = PageRequestDTO.builder()
                .from(LocalDate.of(2022,10,01))
                .to(LocalDate.of(2022,12,31))
                .build();

        Page<TodoDTO> result = todoRepository.list(pageRequestDTO);

        result.forEach(todoDTO -> log.info(todoDTO));

    }

}
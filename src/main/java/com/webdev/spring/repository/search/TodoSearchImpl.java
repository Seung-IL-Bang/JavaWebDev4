package com.webdev.spring.repository.search;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.JPQLQuery;
import com.webdev.spring.domain.QTodo;
import com.webdev.spring.domain.Todo;
import com.webdev.spring.dto.PageRequestDTO;
import com.webdev.spring.dto.TodoDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

import java.util.List;

public class TodoSearchImpl extends QuerydslRepositorySupport implements TodoSearch{

    public TodoSearchImpl() {
        super(Todo.class);
    }

    @Override
    public Page<TodoDTO> list(PageRequestDTO pageRequestDTO) {

        QTodo todo = QTodo.todo;

        JPQLQuery<Todo> query = from(todo);

        if(pageRequestDTO.getFrom() != null && pageRequestDTO.getTo() != null){

            BooleanBuilder fromToBuilder = new BooleanBuilder();
            fromToBuilder.and(todo.dueDate.goe(pageRequestDTO.getFrom()));
            fromToBuilder.and(todo.dueDate.loe(pageRequestDTO.getTo()));
            query.where(fromToBuilder);
        }

        if(pageRequestDTO.getCompleted() != null){
            query.where(todo.complete.eq(pageRequestDTO.getCompleted()));
        }

        if(pageRequestDTO.getKeyword() != null){
            query.where(todo.title.contains(pageRequestDTO.getKeyword()));
        }

        this.getQuerydsl().applyPagination(pageRequestDTO.getPageable("tno"), query);

        JPQLQuery<TodoDTO> dtoQuery = query.select(Projections.bean(TodoDTO.class,
                todo.tno,
                todo.title,
                todo.dueDate,
                todo.complete,
                todo.writer
        ));

        List<TodoDTO> list = dtoQuery.fetch();

        long count = dtoQuery.fetchCount();


        return new PageImpl<>(list, pageRequestDTO.getPageable("tno"), count);
    }
}

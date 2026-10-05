package org.example.course.controller;

import org.example.course.model.Course;
import org.example.course.model.CreateCourseRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    /** Khong dung DB - danh sach tinh trong bo nho */
    private static final List<Course> COURSES = new CopyOnWriteArrayList<>(List.of(
            new Course(1L, "Java Core", "instructor"),
            new Course(2L, "Spring Boot", "instructor"),
            new Course(3L, "Microservices & JWT", "instructor")
    ));
    private static final AtomicLong ID_SEQUENCE = new AtomicLong(COURSES.size());

    @GetMapping
    @PreAuthorize("hasAuthority('COURSE_READ')")
    public List<Course> getAll() {
        return COURSES;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public Course create(@RequestBody CreateCourseRequest request, Authentication authentication) {
        Course course = new Course(ID_SEQUENCE.incrementAndGet(), request.title(), authentication.getName());
        COURSES.add(course);
        return course;
    }
}

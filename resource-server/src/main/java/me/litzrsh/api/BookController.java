package me.litzrsh.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BookController {

    @GetMapping("/books")
    public String[] listBooks() {
        return new String[]{
                "Book1", "Book2", "Book3"
        };
    }
}

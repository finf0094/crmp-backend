package kz.qbm.app.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestContoller {

    @GetMapping
    public String test() {
        return "public";
    }

    @GetMapping("/2")
    public String test2() {
        return "authenticated";
    }

    @GetMapping("/3")
    public String test3() {
        return "moderator";
    }
}

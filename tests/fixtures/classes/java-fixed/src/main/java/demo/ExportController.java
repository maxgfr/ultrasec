package demo;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {
    private final UserRepository userRepository;

    ExportController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/export/users")
    Page<User> users(@RequestParam(defaultValue = "0") int page) {
        return userRepository.findAll(PageRequest.of(page, 500));
    }
}

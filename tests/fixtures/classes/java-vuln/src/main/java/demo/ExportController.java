package demo;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {
    private final UserRepository userRepository;

    ExportController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/export/users")
    List<User> users() {
        return userRepository.findAll();
    }
}

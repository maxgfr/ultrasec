package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
  private final UserDao dao = new UserDao();

  @GetMapping("/user")
  public String user(@RequestParam String id) throws Exception {
    return dao.lookup(id);
  }
}

package telran.java2022.forum;

import java.util.List;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.model.User;

@SpringBootApplication
@RequiredArgsConstructor
public class ForumServiceApplication implements CommandLineRunner {
	final UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(ForumServiceApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		if (!userRepository.existsById("admin")) {
			String password = BCrypt.hashpw("admin", BCrypt.gensalt());

			User user = new User();
			user.setLogin("admin");
			user.setPassword(password);
			user.getRoles().addAll(List.of("MODERATOR", "ADMINISTRATOR"));

			userRepository.save(user);
		}
	}
}

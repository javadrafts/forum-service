package telran.java2022.forum.user.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterDto {
	String login;
	String password;
	String firstName;
	String lastName;
}

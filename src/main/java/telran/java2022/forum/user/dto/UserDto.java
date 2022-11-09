package telran.java2022.forum.user.dto;

import java.util.Set;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDto {
	String login;
	String firstName;
	String lastName;
	Set<String> roles;
}

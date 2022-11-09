package telran.java2022.forum.user.model;

import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@EqualsAndHashCode(of = { "login" })
@Document(collection = "users")
public class User {
	@Id
	String login;
	String password;
	String firstName;
	String lastName;
	Set<String> roles = new HashSet<String>();
}

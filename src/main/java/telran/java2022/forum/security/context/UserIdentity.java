package telran.java2022.forum.security.context;

import java.util.Set;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.Singular;

@Getter
@Setter
@Builder
public class UserIdentity {
	String userName;
	String password;
	@Singular
	Set<String> roles;
}

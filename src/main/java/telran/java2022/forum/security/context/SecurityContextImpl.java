package telran.java2022.forum.security.context;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

@Component
public class SecurityContextImpl implements SecurityContext {
	Map<String, UserIdentity> context = new ConcurrentHashMap<>();

	@Override
	public UserIdentity addUser(UserIdentity user) {
		return context.put(user.getUserName(), user);
	}

	@Override
	public UserIdentity removeUser(String userName) {
		return context.remove(userName);
	}

	@Override
	public UserIdentity getUser(String userName) {
		return context.get(userName);
	}
}

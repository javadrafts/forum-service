package telran.java2022.forum.security.context;

public interface SecurityContext {
	UserIdentity addUser(UserIdentity user);

	UserIdentity removeUser(String userName);

	UserIdentity getUser(String userName);
}

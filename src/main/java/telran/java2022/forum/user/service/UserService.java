package telran.java2022.forum.user.service;

import telran.java2022.forum.user.dto.ChangePasswordDto;
import telran.java2022.forum.user.dto.LoginDto;
import telran.java2022.forum.user.dto.RegisterDto;
import telran.java2022.forum.user.dto.UpdateUserDto;
import telran.java2022.forum.user.dto.UserDto;

public interface UserService {
	UserDto register(RegisterDto registerDto);

	UserDto login(LoginDto loginDto);

	UserDto deleteUser(String login);

	UserDto updateUser(String login, UpdateUserDto updateUserDto);

	UserDto addRole(String login, String role);

	UserDto deleteRole(String login, String role);

	void changePassword(ChangePasswordDto changePasswordDto);
}

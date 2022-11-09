package telran.java2022.forum.user.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dto.ChangePasswordDto;
import telran.java2022.forum.user.dto.LoginDto;
import telran.java2022.forum.user.dto.RegisterDto;
import telran.java2022.forum.user.dto.UpdateUserDto;
import telran.java2022.forum.user.dto.UserDto;
import telran.java2022.forum.user.service.UserService;

@RestController
@RequestMapping("account")
@RequiredArgsConstructor
public class UserController {
	final UserService userService;

	@PostMapping("register")
	public UserDto register(@RequestBody RegisterDto registerDto) {
		return userService.register(registerDto);
	}

	@PostMapping("login")
	public UserDto login(@RequestBody LoginDto loginDto) {
		return userService.login(loginDto);
	}

	@DeleteMapping("user/{login}")
	public UserDto deleteUser(@PathVariable String login) {
		return userService.deleteUser(login);
	}

	@PutMapping("user/{login}")
	public UserDto updateUser(@PathVariable String login, @RequestBody UpdateUserDto updateUserDto) {
		return userService.updateUser(login, updateUserDto);
	}

	@PutMapping("user/{login}/role/{role}")
	public UserDto addRole(@PathVariable String login, @PathVariable String role) {
		return userService.addRole(login, role);
	}

	@DeleteMapping("user/{login}/role/{role}")
	public UserDto deleteRole(@PathVariable String login, @PathVariable String role) {
		return userService.deleteRole(login, role);
	}

	@PutMapping("user/password")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void changePassword(@RequestBody ChangePasswordDto changePasswordDto) {
		userService.changePassword(changePasswordDto);
	}
}

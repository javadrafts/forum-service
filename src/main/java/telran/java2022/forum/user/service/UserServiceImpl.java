package telran.java2022.forum.user.service;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.dto.ChangePasswordDto;
import telran.java2022.forum.user.dto.LoginDto;
import telran.java2022.forum.user.dto.RegisterDto;
import telran.java2022.forum.user.dto.UpdateUserDto;
import telran.java2022.forum.user.dto.UserDto;
import telran.java2022.forum.user.dto.exceptions.LoginTakenException;
import telran.java2022.forum.user.dto.exceptions.PasswordIncorrectException;
import telran.java2022.forum.user.dto.exceptions.UserNotFoundException;
import telran.java2022.forum.user.model.User;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	final UserRepository userRepository;
	final ModelMapper modelMapper;

	@Override
	public UserDto register(RegisterDto registerDto) {
		userRepository.findById(registerDto.getLogin())
			.ifPresent(u -> {
				throw new LoginTakenException(registerDto.getLogin());
			});

		User user = modelMapper.map(registerDto, User.class);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto login(LoginDto loginDto) {
		User user = userRepository.findById(loginDto.getLogin())
				.orElseThrow(() -> new UserNotFoundException(loginDto.getLogin()));

		if (!user.getPassword().equals(loginDto.getPassword())) {
			throw new PasswordIncorrectException();
		}

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto deleteUser(String login) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		userRepository.delete(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto updateUser(String login, UpdateUserDto updateUserDto) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		modelMapper.map(updateUserDto, user);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto addRole(String login, String role) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		user.getRoles().add(role);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto deleteRole(String login, String role) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));

		user.getRoles().remove(role);

		user = userRepository.save(user);

		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public void changePassword(ChangePasswordDto changePasswordDto) {
		User user = userRepository.findById(changePasswordDto.getLogin())
				.orElseThrow(() -> new UserNotFoundException(changePasswordDto.getLogin()));

		user.setPassword(changePasswordDto.getPassword());

		user = userRepository.save(user);
	}
}

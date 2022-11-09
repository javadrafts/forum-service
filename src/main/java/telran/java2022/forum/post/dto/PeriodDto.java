package telran.java2022.forum.post.dto;

import java.time.LocalDate;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PeriodDto {
	LocalDate dateFrom;
	LocalDate dateTo;
}

package kz.qbm.app.controller;

import io.jsonwebtoken.security.SignatureException;
import kz.qbm.app.dto.exception.ErrorDTO;
import kz.qbm.app.exception.AuthenticationException;
import kz.qbm.app.exception.NotFoundException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;


@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorDTO> handleAuthenticationException(AuthenticationException ex) {
        ErrorDTO errorDTO = new ErrorDTO(ex.getHttpStatus().value(), ex.getMessage());

        return ResponseEntity.status(ex.getHttpStatus().value())
                .body(errorDTO);
    }

//    @ExceptionHandler(RequestExistException.class)
//    public ResponseEntity<ProblemDTO> handleRequestExistException(RequestExistException ex) {
//        ProblemDTO problem = new ProblemDTO(HttpStatus.CONFLICT.value(), ex.getMessage());
//
//        return ResponseEntity.status(HttpStatus.CONFLICT)
//                .body(problem);
//    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorDTO> handleNotFoundException(NotFoundException ex) {
        ErrorDTO errorDTO = new ErrorDTO(HttpStatus.NOT_FOUND.value(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(errorDTO);
    }
}

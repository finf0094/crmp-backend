package kz.qbm.app.controller;

import io.jsonwebtoken.security.SignatureException;
import kz.qbm.app.dto.exception.ErrorDTO;
import kz.qbm.app.exception.AuthenticationException;
import kz.qbm.app.exception.NotFoundException;
import kz.qbm.app.exception.StorageException;
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

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorDTO> handleNotFoundException(NotFoundException ex) {
        ErrorDTO errorDTO = new ErrorDTO(HttpStatus.NOT_FOUND.value(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(errorDTO);
    }

    @ExceptionHandler(StorageException.class)
    public ResponseEntity<ErrorDTO> handleStorageException(StorageException ex) {
        ErrorDTO errorDTO = new ErrorDTO(HttpStatus.BAD_REQUEST.value(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(errorDTO);
    }
}

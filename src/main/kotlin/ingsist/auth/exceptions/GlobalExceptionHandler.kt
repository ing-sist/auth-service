package ingsist.auth.exceptions

import ingsist.auth.dto.ApiError
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler

@ControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(UnauthorizedException::class)
    fun handleUnauthorized(ex: UnauthorizedException, req: HttpServletRequest): ResponseEntity<ApiError> {
        val error = ApiError(
            message = ex.message,
            code = "FORBIDDEN",
            path = req.requestURI
        )
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error)
    }

    @ExceptionHandler(PermissionNotFoundException::class)
    fun handlePermissionNotFound(ex: PermissionNotFoundException, req: HttpServletRequest): ResponseEntity<ApiError> {
        val error = ApiError(
            message = ex.message,
            code = "PERMISSION_NOT_FOUND",
            path = req.requestURI
        )
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error)
    }
    @ExceptionHandler(PermissionAlreadyExistsException::class)
    fun handlePermissionAlreadyExists(ex: PermissionAlreadyExistsException, req: HttpServletRequest): ResponseEntity<ApiError> {
        val error = ApiError(
            message = ex.message,
            code = "PERMISSION_ALREADY_EXISTS",
            path = req.requestURI
        )
        return ResponseEntity.status(HttpStatus.CONFLICT).body(error)
    }
    @ExceptionHandler(CannotRevokeLastWritePermissionException::class)
    fun handleCannotRevokeLastWritePermission(ex: CannotRevokeLastWritePermissionException, req: HttpServletRequest): ResponseEntity<ApiError> {
        val error = ApiError(
            message = ex.message,
            code = "CANNOT_REVOKE_LAST_WRITE_PERMISSION",
            path = req.requestURI
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error)
    }
}
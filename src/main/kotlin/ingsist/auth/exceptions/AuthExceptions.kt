package ingsist.auth.exceptions

class UnauthorizedException(message: String) : RuntimeException(message)
class PermissionAlreadyExistsException(message: String) : RuntimeException(message)
class PermissionNotFoundException(message: String) : RuntimeException(message)
class CannotRevokeLastWritePermissionException(message: String) : RuntimeException(message)
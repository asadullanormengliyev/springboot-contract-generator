package uz.zero_one.project

import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.context.support.ResourceBundleMessageSource
import java.util.Locale

sealed class DemoExceptions(message: String? = null): RuntimeException(message){
    abstract fun errorType(): ErrorCode

    fun getErrorMessage(errorMessageSource: ResourceBundleMessageSource,vararg array: Any?): BaseMessage {
        return BaseMessage(
            errorType().code,errorMessageSource.getMessage(
                errorType().toString(),array, Locale(
                    LocaleContextHolder.getLocale().language
                )
            )
        )
    }

}

class UserNotFoundException(val id: Long): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.USER_NOT_FOUND
    }
}

class UserNameAlreadyExistsException(val username: String): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.USER_NAME_ALREADY_EXISTS
    }
}

class OrganisationNameExistsException(val name: String): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.ORGANISATION_NAME_EXISTS
    }
}

class UserNameNotFoundException(val username: String): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.USER_NAME_NOT_FOUND
    }
}

class OrganisationNotFoundException(val id: Long?): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.ORGANISATION_NOT_FOUND
    }
}

class TemplateNotFoundException(val id: Long): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.TEMPLATE_NOT_FOUND
    }
}

class ContractNotFoundException(val id: Long): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.CONTRACT_NOT_FOUND
    }
}

class OrganisationNotActiveException(val id: Long): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.ORGANISATION_NOT_ACTIVE
    }
}

class PasswordNotFoundException(val password: String): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.PASSWORD_NOT_FOUND
    }
}

class FileNotFoundException(val id: Long): DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.FILE_NOT_FOUND_EXCEPTION
    }
}

class TemplateKeyNotFoundException(val id: Long) : DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.TEMPLATE_KEY_NOT_FOUND_EXCEPTION
    }
}

class ContractValueNotFoundException(val id: Long) : DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.CONTRACT_VALUE_NOT_FOUND_EXCEPTION
    }
}

class ForbiddenRoleException(val role: UserRole) : DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.FORBIDDEN_ROLE_EXCEPTION
    }
}

class AccessDeniedException(val contractId: Long,val operatorId:Long) : DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.ACCESS_DENIED_EXCEPTION
    }
}

class OperatorPermissionException(val permissionType: PermissionType) : DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.OPERATOR_PERMISSION_EXCEPTION
    }
}

class PasswordMismatchException(val newPassword: String,val confirmPassword: String) : DemoExceptions(){
    override fun errorType(): ErrorCode {
        return ErrorCode.PASSWORD_MISS_MATCH_EXCEPTION
    }
}

class TemplateTitleAlreadyExistsException(val title: String): DemoExceptions() {
    override fun errorType(): ErrorCode {
        return ErrorCode.TEMPLATE_TITLE_ALREADY_EXISTS
    }
}

class FileSizeExceededException(val size: Long): DemoExceptions() {
    override fun errorType(): ErrorCode {
        return ErrorCode.FILE_SIZE_EXCEEDED_EXCEPTION
    }
}
